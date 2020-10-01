Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUGE3H5QKGQE3XRRO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28CE1280B2A
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:17 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id d21sf135809iow.23
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593936; cv=pass;
        d=google.com; s=arc-20160816;
        b=iLAkFNMIvuudm81SIZyCxmg56Ao6F1yqOf5eMC/0d0vL4E4lQsriT1DLRkjWY3TIQb
         kMCRByp3VI2k3N48dB4NdCvTnridWMTm0hJCGK4IK608El+l3l6wwoHQpRPBES1hen1y
         kLQ5wIps9rkzGO1z0MwPqjND+LgrJNrRRlVdErVHAW4XAj18ksBWHZBvQwT117y3aqq9
         GgTLeebiLC50GJIjVcv9Grrc4m7Vo38mNTy3ACaj3lnG1f61sUDi4jW0o39SSIuWdGa0
         zWycEw5OfJyLgN5bcrwWE2CeTJ4onehmzokn9nsr9+Q/qZx6FAHrU1JpTcKSXiXhfCcK
         8oOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0ArDuLNz+fEU2m4w0WuBwWdfMHmjW8PUSGAar3HBfis=;
        b=qiJGA65GCXjKZ4gz1Ys4A2NTRiDOfdiCO7p1c52vbKNMIIjA7TZ+nlfaw7QCtO5C/o
         Tdff/vXgjcd5zoIlOmL8c1+EukR/Lstghz8p3gPxCoyd7KMjDeJW/BfmbFoW1SDBnv/N
         MYPiirVX2PPHBTThj+kc1FZWm3Ta/ipBWvUyF4zxHeAQFsQEJjVNg8PsZUO4B+9809mb
         AfUprDOjOEQknINydw/fCopvlkqq/kGs05iLt1ViKyrZwhcGU22nrUwjauM+ZXRCNLmI
         0qidbJdaqdv3IQYdaXXEPgmosLCnrFUHorOgg480zBOB99BzqGHSsC0L2JkWDc4M38s+
         +5BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gkLinJWd;
       spf=pass (google.com: domain of 3t2j2xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3T2J2XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0ArDuLNz+fEU2m4w0WuBwWdfMHmjW8PUSGAar3HBfis=;
        b=C8TfBnr/WlykGWilyfzLnT4Q4fBHVV77YoDDXci//fog9gP+ABNJ/ewpUWK+uL/47B
         Id38yvA9lGwIRqXoKPiA8ZAjvn61GKe+I4x/qRD20Qkw35lcH0i7yiSO6FigfeK1xu2T
         zDkvcYdsoOirgY+l5Mkp55fkVs5velEodjpZ5i5AYfYH3sR2LnT/D99weIF0QvjP99R0
         ZzmoBVbIJxHNIf6kc3+zu/+UofoZbQBN+9CdNMzkRG5NWUMYtARyz5dqmwAQuaAdj5wC
         AsPYJx/evlHdCjCX5b7ny/gWqGy/YG77t6RyKdwfN2E0nOBowKn1qtjok6Zd5lSmWBoP
         iqAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0ArDuLNz+fEU2m4w0WuBwWdfMHmjW8PUSGAar3HBfis=;
        b=nKXd8FTTgnXcDoS/V4NcU/vrwoQ1+J7jVHCjJTKjMabR+DsAlipU04gq9E4DlO5vhN
         zWlUdjky0jJmyh5up6jwhmhBiF7sRbCG57+S/VDzMIacKr+DV/DqiJfPBRj9VDjCkADb
         BT18JjAdvF7Xo/blLpQGQ/XGo78QClgQPfUf5P2z7GbCnLJZ8jeXkAsBk+tIx5j63s5M
         D8eviJ6iI+OYIHDe2w3J/+p7lyXmT4LjjvyfX9d8xcFm5iymzzlZit7lq0i9Mv/fIwwA
         Pjg/i59cmySdn7GoQFTCKezixY508Xzezh169nfffTanyfFWN7fYxv0aX3pgHgzPaCYu
         t+oA==
X-Gm-Message-State: AOAM531uQE39nsHEbA0dtFDQaizOE71+sYAwQ5MGsKdbQhRryvz9RMH1
	b6Trs0rz34AAf4CZIZC9/2Q=
X-Google-Smtp-Source: ABdhPJx8C3UbcWmeTyCwCoIOQe+OIa7sBG0f+bVk9mGC2fLLzqcj7NPFRTGouzLyiyip7Tx0pgMyPw==
X-Received: by 2002:a02:ce8c:: with SMTP id y12mr8539536jaq.53.1601593936147;
        Thu, 01 Oct 2020 16:12:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8154:: with SMTP id f20ls1146502ioo.11.gmail; Thu, 01
 Oct 2020 16:12:15 -0700 (PDT)
X-Received: by 2002:a05:6602:6c9:: with SMTP id n9mr7151003iox.91.1601593935714;
        Thu, 01 Oct 2020 16:12:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593935; cv=none;
        d=google.com; s=arc-20160816;
        b=SMXUbdRep+SppWSnaw59N2DagCJeNvhaqe8ZaTTO5L3DinwR5oYH2KXxxKg+Ewabga
         h3JhcESjD4vSNSAxb+GE/u5K0pWQiLSVGngIHTgP0EREBzCRXdGhL+IUzltq7I+/2z+T
         FBDX3w+0xgd9jwmYx+KrI8MTJwd9LkvRlLRodHfbtR6Fktg/d7ysP4vVGKEhCN5vtwH8
         gk9p93azpSRS1VCy7kt3bBkHuOKc5oAJ+BMwYp6OA7gVi6wOoGMrY9BiZ5akexOlhcB0
         3ZD74cA/l6rhnWA2Ahj8HW7j18b42u8PnvAV1Pk/93oQrHuy3C85teCelCdmGijJXDGQ
         eMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SUeSNLKjsRu2tdmPXnlbC/OTs32hqr/cgOt2tHXYw8w=;
        b=Pu8508BiN+7Oh+EJBhQ5yTWEEsJG1vLGC+X0pB2hB0BgohfhTOcuI/UbKwF4raBK7J
         rsOr74n+b0ghZvl7ib6TUXI1PzJVAsq8x2AXLtQ6TBvuVVUIB4GMohJ2SdrEMZzUcF6W
         qsZm3KPRuHl6gzGNi6odP8o2I+qhQPyAqReKPoiozp+v9R/UEMNEUAt49IWrT5pUNAhi
         HfpVHD8159161mRXMOp1no3aNaXdk8OJ2uQMQNMM+UtDpiydnHKa279TprLh8H2OLhD7
         n4Im+/Db8pVrBS8TbQt9bddRGqEljgyaQIWeaSlqi1fQI2OAq1XRa4k4WuvX9+rLmJf6
         NLLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gkLinJWd;
       spf=pass (google.com: domain of 3t2j2xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3T2J2XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id c10si113588iow.3.2020.10.01.16.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t2j2xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 60so73388qtf.21
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:15 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b915:: with SMTP id
 u21mr10296666qvf.0.1601593935127; Thu, 01 Oct 2020 16:12:15 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:39 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <fc672945b196a56bdfbba3cfece6db46ab21d22e.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 38/39] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gkLinJWd;       spf=pass
 (google.com: domain of 3t2j2xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3T2J2XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e28d49cc1400..8d139c68343e 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc672945b196a56bdfbba3cfece6db46ab21d22e.1601593784.git.andreyknvl%40google.com.
