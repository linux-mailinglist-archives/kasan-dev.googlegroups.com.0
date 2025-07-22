Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT5V77BQMGQE7IO2ZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E042B0E395
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 20:39:13 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b30ead2fbsf28550921fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 11:39:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753209553; cv=pass;
        d=google.com; s=arc-20240605;
        b=FsejDuU+lDvL4j43l738ucLQr1AULEaLIXqJL9fTI+t8YbaxwCL+zt2U+Zb2BdfYLD
         QMyEOKb4iNyjaB9YoTDo58WYgZhE1kA8v129uMn1ysDA4LnNLOAtNlmT7E6qumKFKJ+v
         8AYu66FtSUEu5fOx+TqvDtXnAkucMHrA7TaTlJO3eebFZS3macmWkoeFmhYVLUdmNAZl
         D3fW6+8wlTuTuNFEaU19jnHEyzddSdJGnkgdwTPmEJfdCllsXMGFygEBh3LLaX/9vkH/
         rxuCPU6bJiCAMiPawvu5bLbN/MH+KHhe1bqi91Gw1i6n5vP0KUyPMMdlzZBBH4+585UI
         t0Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=WF/ijweB59Ne0NIQsj+qQZTMjV9fqwG3wnDEHVyCA5k=;
        fh=cU+3XdXJ/HmUJxErIGWllpyQmYHYjNh2AFZSvbxlWk8=;
        b=lMQFImN7k8lTBzyjsy6yH605yH4bDOHmwkTAh9HdkuwR+ZgQnn9grwp6zXsK/gfCTg
         CyxZDeKMfexGjmdjpsR2QQid63kHSjZCDuRJZcWvPOMWQ5PQqCfxfwzQdadrPGnnCsrl
         A20grfHwVkEksRM0MDz3a1Cl+Fpiq6wT2ye8jJOg1Xo0w9rNQ+4ClsJEWrSweiqsuMUP
         GFnuOvdztN7/e3yTmrh3QWFiGiyIN8HSbzbNBWAaIaXssVcYRfHHWSWmKOE5WB3GTjGO
         9IdEdDWhsKT/I1VlTJ9/L1IXrRQXqx24pVAwRt0onoPBABPEqIkM49IEjD2/XRs6CDpW
         zN9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BnzfemOV;
       spf=pass (google.com: domain of 3y9p_aaukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3y9p_aAUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753209553; x=1753814353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WF/ijweB59Ne0NIQsj+qQZTMjV9fqwG3wnDEHVyCA5k=;
        b=JVj5+LUwhvjB2hsOEUyl4wBcwt3g0ulZWeU/cG5x2oRWEstF+nT/zYKPyzBOKlcDub
         g4OYinJu9oLXUgX+DWVAYEac1id8BXkkMD+N0zDIjIyCoFv9sU8M2A9jY6aCYyYRFYC+
         pxyXEh0TfABRjpdxif7T+mjmQW2FhgfEBIHxHmgymRU4r1ap9Jp97EkOiEFJAeq2piBe
         +n/X1Avx4LA8p5Iri8q5NAAbsrOArVvOEtqtN+DkCBB4y3EkivT68EziwLMX+DrQv69N
         JTGZ8O2azd1p6trsoNp6BkSAWGLLyL2eztmpLWsA4My6q/3vsz44PfyFwDPipP+L7pgV
         XwhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753209553; x=1753814353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WF/ijweB59Ne0NIQsj+qQZTMjV9fqwG3wnDEHVyCA5k=;
        b=GxfGS/Z3GQvrLBF+ula4bq4Yx4HTWxfnMs0g5DWqQ+PnNq77l9uAB7WDs2BLn/au66
         e7zIoZX1d0LEWoWHRYJYdVNZzJhTqysfnMcOZQ4InxbnwntYLjPgjqG21d22/zq+RQLw
         Gbsx1payhuhoJkSJ7T01yrT2V2F1+8RvWPwLSTW7nSn8ZZcK0PWxGcmsFHdUhhdqxrEd
         egOq+f1g5SBONqcG3+6/nRDoNTIfVmt/r+nXm8sFK4Zp2L+yP6iQkPn+dGOuJuZVspUu
         xyqpKRoZcdkZ1akE8RGGQ5FofpaQW7hXgqzOCld++Obg+Xr0K64kFjDKH+L9nu0MKL14
         6xVw==
X-Forwarded-Encrypted: i=2; AJvYcCWSnhOJsDogsR9mql0EJO8WkGJwkrzIwBMAjXtDH1MYGQoese+XgRgpx+bOvF47Mu7cQOZq7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxt20UMy4j8BRHnlz6y8hvhW6iwVFSluBwTBQo5JPFRIkctvRgz
	JlvvQejO2M8ztbnZQnsdBJqo3z1m/bWaqt01n+qlNNvoT1fg65J3GG4m
X-Google-Smtp-Source: AGHT+IGGR2AlHW02t4zgvw9keN7NPBSKpsWJaqIaZRXTuYKIisvt0xkDpIV1feLcyFNWFdxfrgJuPg==
X-Received: by 2002:a05:651c:1196:b0:32b:7413:503 with SMTP id 38308e7fff4ca-3308f501f83mr51585871fa.16.1753209551970;
        Tue, 22 Jul 2025 11:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfM6UqpnUIeH00rx5THa6v+jSFWDUkUfYJFPz/s6mhrBQ==
Received: by 2002:a05:651c:111c:b0:32a:6413:a9e with SMTP id
 38308e7fff4ca-330980133afls15368391fa.1.-pod-prod-08-eu; Tue, 22 Jul 2025
 11:39:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgAsBxOcVhrURSLOR2BUmvGBGqP5MMA7mkZ06hF8JERZnwaTK7hSx3wtE7VtNAqwchSSU5G5Uzf9M=@googlegroups.com
X-Received: by 2002:a05:6512:1296:b0:55a:305f:6d2e with SMTP id 2adb3069b0e04-55a513ce823mr40430e87.44.1753209548515;
        Tue, 22 Jul 2025 11:39:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753209548; cv=none;
        d=google.com; s=arc-20240605;
        b=aEEoZtq9RqLBHAPjDZ+3hSiBz6OMe0+iTYljbTeScAmvDAcNnKE312hcT6N6EXb94g
         RcJMXMP6+3YTTUn7xCvKn8+ocZUEaV+27ZzVODHTUZ+zVLhijYG9iY0IUt+oTQDtzhnT
         3BwpdTyfTg5xkJi28CG9vVVoJhUhPumh83P003lgThFsNsIqUd8AIxqs/Z2OWb80DbGw
         q5rqmbJuro71xJDMEkx5FWcVklKQs0P5VIHibL8LHdWhQsJMzToe7ofGOk8RDdpz3S6X
         eBrrYICCozBAhqPWGlX71qEWgjTKivTKv5xtV8y7UwDd/zxLBq2d+e/7OU6ByNdlAF/M
         buRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=8JcyrT1yxlGaoNHF9VUuNd45CIqGbNSpnox4Y+ol6RE=;
        fh=FKtsl+M/QJ7esc3LnwoVx8Jk3gjiyOd2Na62tSd1AEI=;
        b=VVPah7/nBMqHd6tesjvGPMExsv2+2viiVOKuRSZ62Y7NZsZynbFc3UtMn+V8glQ7n2
         myuQuXHqdPRJE1g/+BQv7pbfoklWSwqG7qemvrxw45sDzXGR9nvzBpCHuf8qwIhwl58t
         weqMbQ/lTHzr3x2eyHx2YztqgfIizs8cYhj5hlqngJoAnirDw+/n15viBooHwTssD1rj
         HKv3nyHeqqpnIx2skKUQRsycBPGxvmKf9Ejr7w8U3ee0mAvRoqDNF/ej8Rmo4p+6o5ul
         PlfWTRBpBh+Bqmi+KAj5bhg9fssSvLynZ9gj2gw0W3MG3kT07KBA2x+EUhiTXTnmohK8
         buZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BnzfemOV;
       spf=pass (google.com: domain of 3y9p_aaukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3y9p_aAUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55a31d851bdsi251341e87.9.2025.07.22.11.39.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jul 2025 11:39:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y9p_aaukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-6069f1c97b3so5028808a12.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 11:39:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVX+9yUJS1KGdNlmjj2/l/wCMMJPxDwQNMXAdVsWDfAc59a6DqHtObclRJkFBLWzCdAXK3M2M676yc=@googlegroups.com
X-Received: from edex4.prod.google.com ([2002:a50:ba84:0:b0:608:3a2d:685c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:90c:b0:601:6c34:5ed2
 with SMTP id 4fb4d7f45d1cf-6149b410255mr50137a12.4.1753209547885; Tue, 22 Jul
 2025 11:39:07 -0700 (PDT)
Date: Tue, 22 Jul 2025 20:38:35 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250722183839.151809-1-elver@google.com>
Subject: [PATCH] kcsan: test: Initialize dummy variable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BnzfemOV;       spf=pass
 (google.com: domain of 3y9p_aaukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3y9p_aAUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Newer compiler versions rightfully point out:

 kernel/kcsan/kcsan_test.c:591:41: error: variable 'dummy' is
 uninitialized when passed as a const pointer argument here
 [-Werror,-Wuninitialized-const-pointer]
   591 |         KCSAN_EXPECT_READ_BARRIER(atomic_read(&dummy), false);
       |                                                ^~~~~
 1 error generated.

Although this particular test does not care about the value stored in
the dummy atomic variable, let's silence the warning.

Link: https://lkml.kernel.org/r/CA+G9fYu8JY=k-r0hnBRSkQQrFJ1Bz+ShdXNwC1TNeMt0eXaxeA@mail.gmail.com
Fixes: 8bc32b348178 ("kcsan: test: Add test cases for memory barrier instrumentation")
Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index c2871180edcc..49ab81faaed9 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -533,7 +533,7 @@ static void test_barrier_nothreads(struct kunit *test)
 	struct kcsan_scoped_access *reorder_access = NULL;
 #endif
 	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
-	atomic_t dummy;
+	atomic_t dummy = ATOMIC_INIT(0);
 
 	KCSAN_TEST_REQUIRES(test, reorder_access != NULL);
 	KCSAN_TEST_REQUIRES(test, IS_ENABLED(CONFIG_SMP));
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250722183839.151809-1-elver%40google.com.
