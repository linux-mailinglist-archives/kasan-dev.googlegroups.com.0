Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSPW73YAKGQE3NRPR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 21A1213D176
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:27 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id x22sf7879140pll.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137865; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRmxKtK2xe2mzGR2aoHK0zkd9EJos7CjK2uFbRmfrWqj1Ox1bIwbxzh07RDpftCDvw
         1GGolLr71wTswgwc71oAumZqWPapluGFaluxb14Ie8gLpvAP+Q/ymMEaAjvFjGzT6y2v
         788LDQtKvGbAevvTl8qXwMNGM7ZuDebVKZep1H3tewiCwo98F60JGIDPZ069p+0mmH9S
         luU1XXsqr5yxoc0A4sSpA5O/0TrcDFhuzorqsi9WOV8+BaJ7uQAEh7hsxcMJ1BqnDskw
         fK+3WVFtVczj4jMjZygrFuGdqbRj0GE2MKGkioofE3WwRhFCpSzOqg3YSbBghArl0DYF
         KX3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JVytFLIV6o3sY+tBSp3gQg4jQ3IpHWEaPrV/WKJjfsc=;
        b=jnCJI/bz91h5G0PaqG4PZxhMzjn0ViB33B1Pt+4GqatpdUB9mVWu13mqgK60tAlzbe
         MmiAR2q54saN4iGdfzGjQIlEIm2Bwl1mmM5fyZtw5pjvmm+FyzN3bylPzzIEM3OjsFPD
         SApC5NWfu2y0TirEe1E1qu8sJA9HW1FZVuYVnV2TCmMiLmZIHeE9vtosyDCMCF2cXsfi
         yMP0d2KKHpd8e7Z66yPFwDKtMjds6HccVLjksaz4sFzzdb5fLs4RQMGnS7ytc+9JibQd
         Q0my8nOEp3kPvDRt1SPwBNBxxz8uQQbK6Y2607Ccnv6xX4c4E28O0MgheGehcsGiFbKw
         fZfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YBfsq7Ez;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JVytFLIV6o3sY+tBSp3gQg4jQ3IpHWEaPrV/WKJjfsc=;
        b=hHv9nhPErvsnqZ47r2Ot8mWeATlse2PV0y72SASXpFx+nWmzzoCly3OiBSA7td78MY
         L8+BTceG30SRPb4LWwyLfHYP+SGOgYA7vqO2c4CLvHcDxy9qjzoXsE8rY4m4dhqQ4IPC
         NtQRD0Tzj3hp0+A1u2gBpqy7ctJpebzqdu2XAMMb+fM4mT78rPAjTScjcFQm1+8qNndO
         /SZerE613gZJstA3WkWHU/BSiZqj49TA5JSKMz7S82cVObOoKJldu33qz/S9f3DMS6zg
         I4Uq+1GIEa14CP1tpyAr9yOaJmx/P5jQpq0lFWOOzwF8Apl0eJphaImrUQOiWN2Okpkl
         N2ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JVytFLIV6o3sY+tBSp3gQg4jQ3IpHWEaPrV/WKJjfsc=;
        b=PZ2KUbIu8eD+KSL/QlsaBNVn4Gi8nzK55xjdaR2xUZTGCr40cpcZi6Ww2U3mEvHvzy
         bzcoJQSxnq7hVAYbL4WDCLDJ3gkBP/76QAVZCLyEtYE9L4fqLKtlWJl710H2ZBZD+GaE
         xnZsiK550cZFKq7kIS1iO4rug0X94nz4v+Rn5GEsCxpEOIWZcSfw4MlWypM5CZiSk1Zf
         7EpD3ydnLlOAenQfnkXH22F+X3h//5mV1mx/9N03ZfPCXpHfLAK+U9SIdxwj+Ojv/Lg+
         hlef8kZU6pNe3lgkmNDeca2dtlRqVmt9iEoHk+DS0OT/1p1hY93Md70UIEPTgFi1RXgm
         zclw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU+Eo+TPyQBiStl7isyfXLFNF00z8DJEnf+d7J+kfH70rnUbKJE
	3nVx0LK8msY+4lV5pKPqK4U=
X-Google-Smtp-Source: APXvYqynH2AWZDu0gdxn7dCW5k3OyTt48SoBaqzJMy2nyFBxTpdjFqjbhJ3P80OTg/TkpT9UM+FmrA==
X-Received: by 2002:a17:90a:804a:: with SMTP id e10mr3574497pjw.41.1579137865857;
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad46:: with SMTP id w6ls346452pjv.4.gmail; Wed, 15
 Jan 2020 17:24:25 -0800 (PST)
X-Received: by 2002:a17:902:d902:: with SMTP id c2mr27692988plz.298.1579137865445;
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137865; cv=none;
        d=google.com; s=arc-20160816;
        b=fovCAaKbAdekUw7+KO3pjQN+AeeYCLK/EzOfJ80VsO5cgyemwvqOQQO0Y9T53lwa1D
         Zv0rlTSBW2LxiRjVKPkqONBP9/sg27p0sFWe6eraDtyAQi8BBba411aj4uxFDvsZzTkt
         MJw4se+2FAAZ+qWtG+zATDZohOdG6WOxFHShfZmqy8Bw3nXhvJibov6774urMU8Q5w3F
         F4vejthS5x9U+V4qq3X+UVawG7qoCGZcvZyUvqLbxsSNtOvxiFsQOqNQiGlwRNCEk/aB
         GHEGNlY3m56S7w10oSG1NDC/2VoP98xrmafBwCIoDxJeVkAwmepRtBUGJcPCTTV6riBJ
         m4UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8H0Ju2Tzkc7Hi4GTApYP4I+j3crkZ0C4oDWnN2FFbsw=;
        b=oNqY9v6b2zCuDnCjdel2PciQxCMyo4s0Vh0ETdDgzxA8j3/aUw1RrdAJClTG7YtiKH
         L5ITUNreynFWwPA816KfU48jV/qP/6LmieQmR3zzxttHa8bPSP0ckSFSOn+31EzZkAFE
         DKhlQtmPi3law7DpvY+9UwPrCmk16zodA4eL655aDFNQcNpjdMiZ8/w9itPBiAPO+9Lf
         X1t3JIXfHDgBagNv6rNENOpyaB1y+2d4+QEc5m4q5lD+6R2hS28bFdN2vosf9nNaNE96
         SgdS/GMzfPhf5dazOrNnITgV/O8DcZ419e01aAyDFPDhjYFuaLCA9UeM1oTcxufM0RqU
         Vd0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YBfsq7Ez;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id d14si969736pfo.4.2020.01.15.17.24.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id k197so9036982pga.10
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:25 -0800 (PST)
X-Received: by 2002:aa7:98d0:: with SMTP id e16mr33457061pfm.77.1579137865146;
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d1sm1046181pjx.6.2020.01.15.17.24.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v3 5/6] kasan: Unset panic_on_warn before calling panic()
Date: Wed, 15 Jan 2020 17:23:20 -0800
Message-Id: <20200116012321.26254-6-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=YBfsq7Ez;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543
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

As done in the full WARN() handler, panic_on_warn needs to be cleared
before calling panic() to avoid recursive panics.

Signed-off-by: Kees Cook <keescook@chromium.org>
---
 mm/kasan/report.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..844554e78893 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
+	}
 	kasan_enable_current();
 }
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-6-keescook%40chromium.org.
