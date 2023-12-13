Return-Path: <kasan-dev+bncBDXY7I6V6AMRBE5K5CVQMGQEGZSXOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 890BA81200C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:33:24 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-33349915d3csf5521909f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 12:33:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702499604; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vz4/iBPyPkXouQl793DGnjo2Y8Nww44xbRMSy7/q8POxYFYLo7ORKE3rKuwT1LrxTa
         HYKjv9G9BXEARfSyRHMSuIkwX+PPImOiDFkqeiSiV5nuNVnuvtx7NtpHPQ8Lvm58oKQO
         g4/FFEv997gZGnr0pTm71g+7/mcMoUC1YDe6AmTCKTqNLeV9P83AuBbrWrmjGEOkptLm
         DMaKcqvIQcnfxT/Lw3rQkCsuO9MIDR7G7BYLB+0jPX7yPt/La4HYcRY72qkNsjdvducf
         ZW5pe748HzdI42ZrzQL4cuuKrsYU08cZ3v3Uhh0IYntNUMuqwmbu4VE0lgZDHkxUUnNH
         wPfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=s7b9MV/T6JlWS0t4Wj5ytyAgO7k9viSdScRILa1O+UM=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=cQ3Bov/3Tk6HqYF8lQDW3UwC3mvVcK1pWgpftdd0MiyeYZojPvtsK60CoVKZDKV1tD
         gcotBELiSzHq7rk+NgbrHRhQbPwNZvnEgQmr+iBJ8oKZ9Q7kMkXbwQRee3UqCB0isSCF
         vKRGUrzh4UkaXGLt2GP5s2aRxaR6R8qWzigWYDtLmvMydRzsY9h+WxXw2YJ66v5/qTer
         GETa4ADVOwgqthhY2nXrCjN4P6nw9nfGH9M6if6p57Bu4PHbx6S9zjwCIWpHimX6VP+m
         6fvxnJ2I6kMUXlzzLXlJyqC5Yk0wAc1As35N8u4nBQXB9gdrV7c9oIMSDcOPOqBnXV2i
         +tWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=mCqHQayf;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702499604; x=1703104404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s7b9MV/T6JlWS0t4Wj5ytyAgO7k9viSdScRILa1O+UM=;
        b=ZCFF3Haugeh/jGl/dJMPoSBT+lbHb9EntUe5wSO2r6chXzdiAt4dWFit8F1OzfQ3ol
         eIAA4g+vYzjKjFuc3VrDXSoRanNm9h2qHNJ1qk4OdUlWx2efH/7T7bv8Ec3hKugeqaBu
         LsXfmOb2uI5dVtNTAwPWNSVNb0g3FY7h0CTidGN8L/7XpG67RhKw+wFzV2gXHaG7EIcZ
         b6snLgzuuAwyqb5TYrDDjfVGCVMxV5z2EYG9/WXC6M5RgBPoECGDSsrerqfzUB9BbogG
         6sZMutBzK9OUAyac8YxGPe8hhsk4C4oJ7y30ney6NLj233bdpFNAENurVbgIXR4macUM
         y6vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702499604; x=1703104404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s7b9MV/T6JlWS0t4Wj5ytyAgO7k9viSdScRILa1O+UM=;
        b=tj0u85HVKWBJV7QKea+bilRoZY5aFokd6GKgRuhQ/3FPhW4sYs8gjFcsQgKbfONbrp
         fsx3/DsOKYdpIqi0ksfRurY6oIvL4VObKtCqgTY1EJl2gYzCNaPN4ESx2QWk1MNuKXio
         gc3+tTdOuiolLkfK9IL3KyjC1Z9pYasvh7/szgIPq8ogvevvmRZU4I2xlhTdveyApFUR
         Z3KrhXywYdAZf3sCyPAR2PwxBjb3AlAQ4gVgDnQJ64R+Mydy+44kaWuY5X8fIwXRZPmj
         DUsE1CzEx/fzvcCgBM7sFN7lsV8yCfsm3yx0Guz6gTVTRjwXrxV8OHeJm1WkX376og3c
         dCRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzuTZRwzONoD1IYvX9SibjawPotSCM17c9Z4/oWU7WsesAiyo5u
	ha9MaK50ZxIJ9BDvPdvox0A=
X-Google-Smtp-Source: AGHT+IF0r8XSYhGYCqIVbCAEm4WclYBClrzesasEke6/586QnbXw64n7Wtzw0eJhaGMhzF6IlGxPUw==
X-Received: by 2002:a5d:6242:0:b0:333:5c07:9e59 with SMTP id m2-20020a5d6242000000b003335c079e59mr4428104wrv.10.1702499603812;
        Wed, 13 Dec 2023 12:33:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:333:33e9:2565 with SMTP id a21-20020a5d4575000000b0033333e92565ls3307147wrc.0.-pod-prod-06-eu;
 Wed, 13 Dec 2023 12:33:22 -0800 (PST)
X-Received: by 2002:a05:600c:2d52:b0:40c:2e1c:8f93 with SMTP id a18-20020a05600c2d5200b0040c2e1c8f93mr4076331wmg.179.1702499601938;
        Wed, 13 Dec 2023 12:33:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702499601; cv=none;
        d=google.com; s=arc-20160816;
        b=oAUSxVCcLpczxv/iD9dt2t9qCewYutMia+OZI4KgR7WD9mUmXbpGRbqZesgGttz0JX
         70nQfEBIjwqKaOuEb441mo0rDX9OYootOAXIF4tnixmw4X5y3M0Qn57U5an9dZJqPTAF
         Z64kh3SYEez3cSlhjeqakjix+fhnMM2qbl5yW1s0ql7521IcmobaBk1CCY04qomLy+yf
         KWxO6VLZPLUR31TMoXyftaga1yqiUwS0jmKmNBMu9cjqNkbIwWGaEZl7pWaNxsxhpdJy
         eZS2R5JNNYMdQPlXd5dryrYB8GfHawlPWVJkxGkS7seimMNays3SMBzakTjW1DACi543
         iy6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qNQI5S3fkIj7NrMfmbJzF3XH+7YYWzemWytVmilYcq0=;
        fh=IGropsY/f620dSTjnkF1U3l/yVuB1Ulli/O+nFZzzpw=;
        b=Vl50pLhvEhM6b0fDg+pbTXICDEyM3z3EZYs/mNPsWMOqsKVVa/KAroSjgx/ONKxiUw
         JC6pkIPDfbbIXkXfokHFyAz08DgFNppzaKzlZUDWs0HLYWW1pzizlHCgPPkuZHQ1uCam
         1WT1AAJx4pbcH9zDtHdo+p5vQqNil+QD4nVfERNUcUt18V0w4vp+4ydls0bhUfI5Ot1s
         cPh6ySennemSjCKeQWqCZGf6ZKVYEEmJjFGgHC80znSudsMmhx94t70NrUBN+ZCVOACy
         ESm4jR3HdK3Fh6SViPQ/o1KUFPwD3lCRkVpr/JB6BAoyrK2vtGW1LrnhsCUae4O0xiix
         iSoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=mCqHQayf;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id c26-20020adfa31a000000b00333463f5f71si44899wrb.0.2023.12.13.12.33.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 12:33:21 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-3333fbbeab9so6251048f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 12:33:21 -0800 (PST)
X-Received: by 2002:a05:6000:174d:b0:336:36fb:84c8 with SMTP id m13-20020a056000174d00b0033636fb84c8mr990697wrf.107.1702499601505;
        Wed, 13 Dec 2023 12:33:21 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id p10-20020a5d458a000000b00336463625c0sm136243wrq.51.2023.12.13.12.33.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 12:33:21 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Russell King <linux@armlinux.org.uk>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@atishpatra.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 3/4] riscv: mm: Only compile pgtable.c if MMU
Date: Wed, 13 Dec 2023 21:30:00 +0100
Message-Id: <20231213203001.179237-4-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231213203001.179237-1-alexghiti@rivosinc.com>
References: <20231213203001.179237-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=mCqHQayf;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

All functions defined in there depend on MMU, so no need to compile it
for !MMU configs.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/Makefile | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 3a4dfc8babcf..2c869f8026a8 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -13,10 +13,9 @@ endif
 KCOV_INSTRUMENT_init.o := n
 
 obj-y += init.o
-obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o
+obj-$(CONFIG_MMU) += extable.o fault.o pageattr.o pgtable.o
 obj-y += cacheflush.o
 obj-y += context.o
-obj-y += pgtable.o
 obj-y += pmem.o
 
 ifeq ($(CONFIG_MMU),y)
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213203001.179237-4-alexghiti%40rivosinc.com.
