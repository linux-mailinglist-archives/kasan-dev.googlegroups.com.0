Return-Path: <kasan-dev+bncBC6OLHHDVUOBBH66ZD4QKGQEYY746NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B6BC0241607
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:44 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id g6sf9706836iln.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124383; cv=pass;
        d=google.com; s=arc-20160816;
        b=aTdcVPRvdrbuA9XqxUUjkGIZZtGPzqPl7a/0EfMFlDQee3Y12AbquoIUDKi+QEDOCR
         HPSGCfiOmUQqR0jJgxIn27JL19VHbqThjQ3ocA/kt3Oub/ZKTYlJDwfu68DX4hZV/5NN
         y2oNvzuuTeeG56bcmQAz0AS45lbNZWKuWxPYcoUCPOrhU0k2j35GAwKBxB3LYVJb2VW6
         lFl+yM8JMbHwxz44KyhnsibDol+O69DifhxqGR1rCLBzJkXfbHINI+NW/wgbcX6Niov2
         6KsYmKsdOa4h3SHqvq5HhYAKa8bEU34Of7kDd7/PEQAoedUeE/TP+Eu+qAaVfmICUxfj
         lUSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vTEOLs5/wZglZoLisdtTRmrbkPTIPYwsJMw5M/ZSQJ0=;
        b=GxXvvOF2/BFEIQGdQLElC++Xk1QqFT1veXKhamUPtwICtEvCFNj8RY6qgBfituazzI
         oOwB56mUAPs5jp36pAsmf6DXS60PYjv+TjER6deqUtfDrdq009+ttStYIDHyG/XEXuLs
         giAISaQycGxdwLDDiDAxXN3Cnh5Yjiik1lf0WBPNjI+MSQI/s/9mmTNoGK0jfe3kRGAX
         3JIr9N4RivmjcxCge7X60ia/n9tPuIlAlTorFloiLxEr7KApDkqJDlld23KdoHxRCW7s
         pbptlISSwHpGb1P7ay0k2VrIK7dj+Wm5JTrGL51KCL8GIfxrf3Enqz409feYe0qJPcYM
         9ArA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="NowArW/W";
       spf=pass (google.com: domain of 3hi8yxwgkcuukh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Hi8yXwgKCUUkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vTEOLs5/wZglZoLisdtTRmrbkPTIPYwsJMw5M/ZSQJ0=;
        b=N6E539DUJ16WhjlQtWWunW8njbZO4bwS4WBlxzCfptDuLlnui2wK3i3wHpcAe5twZf
         nuvCA6JlB/gs6QjT4/oklRdeksTldfj+EIu1F7jRpt7XY/mofKW9gB8Tt7BiE0PLKn0O
         lf1weAFffpAJIdfbPMEoxGx3l8xwoVjAV2GZo4/UCifeTXkDQu87qr+BXfYddahEdH7T
         poQcvubJG2IIipehw+PqInmgcRMQN/2ylPtugBYdOBpAWuY6KWNbd0GbFxXIGsCfGaly
         BANNNz4NxQHNqSiYFRJeF/2hDXAMwHyLLzfxbD7WkF04QpxOvUmO7PLeahJjsRSQs3ZH
         JDlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vTEOLs5/wZglZoLisdtTRmrbkPTIPYwsJMw5M/ZSQJ0=;
        b=GOog9uoAxmlFtajlQZp+Uw4wb52SPqYVXEDfjqoefEh2G9c7HGH67YEVbXmoUAJn4K
         bY5lChOcz/SS4jHcKDZllG0UvTqglRq+i6LbOluNt3+aGTIcb/Jsh2RpFGDhjGiBRVcT
         XushNkwrRKXZOuIheBjEuTEyWs8KYEoMSTmPMvNwxh8d21drhBOsvdb2Sb6Sq3/9izG2
         pIstLgza5b2DdYvmU+M0jgPMEU+Kvyt2Yvvf+rPy6X2ObqTp7hJTmGyKs8OB7ltU1kUb
         o0qP9Quq4rhXjSlU6d3WPqGUMiBDkURKyzc2Xi0DpS77/Os0X476hEq+Jx/Bch4QDL/D
         HqSA==
X-Gm-Message-State: AOAM532vO649WwJdLgJrZFel1d4sq150UkJk9eI4ZEck2tculCHNaGpd
	pvYzsD9WhDV6iOjCzjE3QG8=
X-Google-Smtp-Source: ABdhPJxn86o8V/dVP3qTm83MpRjDbvY5RIEKLiUA1yUl1ggpWDi/YUuCfiDvv4EEoo5wO8BZvh6WpQ==
X-Received: by 2002:a05:6e02:bf1:: with SMTP id d17mr21479696ilu.261.1597124383439;
        Mon, 10 Aug 2020 22:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:84d6:: with SMTP id z22ls3282359ior.4.gmail; Mon, 10 Aug
 2020 22:39:43 -0700 (PDT)
X-Received: by 2002:a6b:c88f:: with SMTP id y137mr21313339iof.55.1597124383031;
        Mon, 10 Aug 2020 22:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124383; cv=none;
        d=google.com; s=arc-20160816;
        b=kMkKR64wAnYa5cPvCiBkX1vZtEYWRY1wwzjPjOF/Z4ufWdTUripBEG3vui3mvAb9s9
         Af8SXIvx+K1H2l95zqWVyweBrNIQB6cYWCQrpcykRpUrEutBmSLDOU2Zb/ZtPLw0nVPw
         y/3SCZ7Um/KS2VygMZtf9Ycu6Md1OxyzzggHjIw/3338ScqW0FoLQz9mKKTxwA4DH5gg
         oRCnEVcQumEtO2DXqHRv46klczoYZVAuJbtoLF+08geW/kUiOp+/Ruux/GJargMtqMCe
         LxdiUkJpEbBbLGmvD2eZsZMzn/Vy0qSS+5Tpmr3XTTvNCFFNZ3PRcnGeddY28EgAZYbL
         Gt2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gAVP1K6ZLdiDBp4x0JlTDJszv82bsLWnDKbp/k/SAGw=;
        b=lgLeccNu8RzT2spYVEBr+Cf+IFY4/SBgO346t3Lyi/C7vNnlHlhZpmmK2j7TSySQT6
         dpAeIBHpD2AMZOqMw/WCSBmBWjUdNgTJYpyobWKUmuJFkvcVbjhhf0CKOVjcVGIU5aGX
         EVvYo1mKahoq0MaI4zpUUajLe2RTHlhZUPcXGHP69AHIG2jf3Wwa7Kk12asOPLu/pgd2
         hj1aGTKuF/nWisU9yzBAu0qsHxTrdikG9e7q3LlL7RprcLJPid9Ek5jMMh5gM1OAKWXM
         bQO521qk3FrgC+ZdYqD6WqSl/U+IVi5QRA1kyAjAdkBBFLDzRdvCckLyp4I5uEmEaQbn
         fJMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="NowArW/W";
       spf=pass (google.com: domain of 3hi8yxwgkcuukh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Hi8yXwgKCUUkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id z6si1187979ioj.0.2020.08.10.22.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hi8yxwgkcuukh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id w15so9108946qtv.11
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:43 -0700 (PDT)
X-Received: by 2002:a05:6214:724:: with SMTP id c4mr32552143qvz.0.1597124382423;
 Mon, 10 Aug 2020 22:39:42 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:13 -0700
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
Message-Id: <20200811053914.652710-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 4/6] kasan: test: Make KASAN KUnit test comply with naming guidelines
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="NowArW/W";       spf=pass
 (google.com: domain of 3hi8yxwgkcuukh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Hi8yXwgKCUUkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

The proposed KUnit test naming guidelines[1] suggest naming KUnit test
modules [suite]_kunit (and hence test source files [suite]_kunit.c).

Rename test_kunit.c to kasan_kunit.c to comply with this, and be
consistent with other KUnit tests.

[1]: https://lore.kernel.org/linux-kselftest/20200702071416.1780522-1-davidgow@google.com/

Signed-off-by: David Gow <davidgow@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Makefile                        | 6 +++---
 lib/{test_kasan.c => kasan_kunit.c} | 0
 2 files changed, 3 insertions(+), 3 deletions(-)
 rename lib/{test_kasan.c => kasan_kunit.c} (100%)

diff --git a/lib/Makefile b/lib/Makefile
index 6ade090a29ff..ed26f56ceda2 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -60,9 +60,9 @@ CFLAGS_test_bitops.o += -Werror
 obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_HASH) += test_hash.o test_siphash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
-obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
-CFLAGS_test_kasan.o += -fno-builtin
-CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
+obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_kunit.o
+CFLAGS_kasan_kunit.o += -fno-builtin
+CFLAGS_kasan_kunit.o += $(call cc-disable-warning, vla)
 obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
diff --git a/lib/test_kasan.c b/lib/kasan_kunit.c
similarity index 100%
rename from lib/test_kasan.c
rename to lib/kasan_kunit.c
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-5-davidgow%40google.com.
