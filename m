Return-Path: <kasan-dev+bncBDXY7I6V6AMRBF7TXCVAMGQEJRNCVDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD41D7E7CDA
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 15:09:29 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c563a2a4f0sf20775401fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 06:09:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699625369; cv=pass;
        d=google.com; s=arc-20160816;
        b=d+geY+4bS64xcEe5lYCFJVO6iqowty6boPjiF83+uk0rMGKJU8WFgZjNTeXInVMGBw
         K2bmU3GYJcX23Bl0B7ibw5zUWyGujACa/0nw9X/wfpNQTAr0VwwXUrJvmz8H3tVsyCgn
         grbrmis6Vpt6+pYzSgBcev4m8d2zFelSiWowx3JMb+2o6l4Prf35uGrh3WU38VZrmvbE
         dGQpq9L5vNJCG3rnftHU9+5iyJv1y+vJfrcpX60x9sLm6AdQAv3WyOkWGy4DfoHgKDc/
         IIjQhaI4nCRKFnZcQE1e5PECmgi5Y9laSfC6diQsizwNqSIJyCn6nWEgsk3oM3SNRmFp
         jG9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CP+Z2tZHP5IF7ZPrPEUr4jaXUU5z49H+AbW5UL31yeY=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=EA1lkLjr1h85LajfLleN12OZ5wWpiei0LULr4sqxM3IG9LAZWpHt7zFR7lqdZqSd46
         EiJx1Da0bGL7ThWDlU5bXPToAKQ4FUwVAi1VZtVkSAqXL0YFRz+T06OyFVfO6YFu8mm0
         MhKfRDafJ68+Pe7zv0LMzGhAY60gXnoNBdBKVdqTEbzj1xN6JPBXLbqwPeni4yShe/Au
         MEzTYgIhBN+JAWRkStVS65LH4ky2Kf2ayFvTng9cpAGUUqFk2uFDbrxRgO9liA17baOK
         BNE963dt0Onar8FAg8sJn010BH7/KCb15Ke/19toA8T1d9Ho6ES//GsRdIhF6Gctj8Jq
         Qlqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ML2wfeKT;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699625369; x=1700230169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CP+Z2tZHP5IF7ZPrPEUr4jaXUU5z49H+AbW5UL31yeY=;
        b=RHADJQ4pC5HZIEQV2csWemNf0UV2x38sK1RY+1fsmS7m9sDvBwvesbeJCik4J/rWhz
         kGtxtLeaibWxqTIHIaHv8479fTHBnrkyag+FwBABWdooA6legi3ezEN+nC2EDaZy1hKC
         YXvDZQlL2fU+z06StoySkadMabEn9Qs0uaI9Svhm3T4oEDImkvO5P0yiCQ4NINAncfsh
         sBy4IgDawxWqAwp5+AEmH9qrsv1Y1SU/QQ738I/UDphgVt4hooTFkk2VgXMzm+hNtivC
         5TK6ORbiqAwhJRptJyKxlA+D9ASYUYdsLOlhq+nGBfsLH5Ng0OfbiuXu6XbYNbppBJ9M
         WLoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699625369; x=1700230169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CP+Z2tZHP5IF7ZPrPEUr4jaXUU5z49H+AbW5UL31yeY=;
        b=OSnrraFvQendhjdIdpgBzebvc70L7FZkx4TiSYC2C3WGO6plZ6mCxrAB7PzneJrcQu
         00CdAbhbRh6olFdrYjVG2rAfd/KUcIUtxviIu5DvzJYGmlEHWZA5AOIxfMdiMo+J6SuM
         lzmhlSFp4ssgmu65NlLwqy+XIssRTlYSwjGBQ6c8WrSQt5qfIBQrVo2IrNp3+VuVooaY
         jqSg4vVT89k6uJkYe019HZ1BQZPVeV6N626Py1pbPPAs471zN4oiI/47DvLrctmjiMf+
         dp9uVMGF2wCrTy47TbefzRRxgmYBJm7cbI70r9VqP8xNiedF5t8P8RGHVYL/Ivil6vHg
         OgPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyQZkfZ50BDHl7as2n/sOPXhgI/ROrnJBBfmXL382KFuRFuidRK
	XA/Q58ZTWNznLhO+xyTZpX0=
X-Google-Smtp-Source: AGHT+IEZfk4vpmDTm3tTRaA/tA+0TmWImTNDpPgUUxylycckx2k/kPFDl0GYwtxmDEwIfPx/Nws4sQ==
X-Received: by 2002:a2e:9c10:0:b0:2c5:d10:248f with SMTP id s16-20020a2e9c10000000b002c50d10248fmr6308480lji.49.1699625367938;
        Fri, 10 Nov 2023 06:09:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b557:0:b0:2be:58d1:dc38 with SMTP id a23-20020a2eb557000000b002be58d1dc38ls197993ljn.1.-pod-prod-06-eu;
 Fri, 10 Nov 2023 06:09:26 -0800 (PST)
X-Received: by 2002:a2e:2c15:0:b0:2c6:f51f:c96d with SMTP id s21-20020a2e2c15000000b002c6f51fc96dmr6506418ljs.13.1699625365967;
        Fri, 10 Nov 2023 06:09:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699625365; cv=none;
        d=google.com; s=arc-20160816;
        b=v8bo1hopCZ2romFep2Ii5yXobmPYK7TFw8ihrw8NEsGobE+LaH2CC1XPrOVnkyVSj3
         gtS8GPuy9V0IvX0c0PPjoXaTAafrTmYUJxIN3jrzBTdfI+LJIZkqHun0qoT+nFxgzntq
         haREqckUlreKpEE6K8ySJnXFi4XCW8gipborCiD8vrbQC3wv3xDiy35kYZXwQw1+MJ16
         51w7y0GX5Cms1GZN2XIIVvJTuxmuCAOqqo/D7dNHKrXgo4Oejw8iPt6vUqtTCxRLZONa
         +qhlfP9tOuORmCjaCoXiX1PCR+JslvHZJ144FJQrNF49PuhRSXI/43etwHqbvuKx+/1q
         ZiOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TNncknImGYd0G7MADnDhbFKl7Y37Hs80keyCtMwuCbk=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=kxzW5As0+6P3xEvYtZXC9VmT/aLVXyO5jJfNyh2HxsQOSSHvpi+9HAdhLzWQ8Lslcx
         AeW1lBKR7kuJJJKAxTYhiIu8lne5kGOUXkHhngT+nv2l64JZ76h/TDPHyXm2XDMKECjh
         rrpsTIsBa/5bgwBGL6GjvqnFc+Rf+pO681cWnO3KSpKLaFryIDEkUVSBZmtdXuxSWVWD
         wSQxEGa0bPC41LSOE/B5+o6pyiYFeNLxnGMhO+hjCoU8370DFFfaMv+PGOJj9ohhcw9H
         7VqGuIAAXLUqdhJwMR7LMQQDIhKpYo5nGF8wteirZWQVjxjIijI+M/pF/gdvdFFg++W/
         TV5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ML2wfeKT;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id h24-20020a2e3a18000000b002c12145a0cbsi1075918lja.7.2023.11.10.06.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Nov 2023 06:09:25 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-2c834c52b5aso5593691fa.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Nov 2023 06:09:25 -0800 (PST)
X-Received: by 2002:a2e:2c15:0:b0:2c6:f51f:c96d with SMTP id s21-20020a2e2c15000000b002c6f51fc96dmr6506404ljs.13.1699625365568;
        Fri, 10 Nov 2023 06:09:25 -0800 (PST)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id b12-20020a05600c150c00b004083a105f27sm5173099wmg.26.2023.11.10.06.09.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Nov 2023 06:09:25 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 2/2] riscv: Enable pcpu page first chunk allocator
Date: Fri, 10 Nov 2023 15:07:21 +0100
Message-Id: <20231110140721.114235-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231110140721.114235-1-alexghiti@rivosinc.com>
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=ML2wfeKT;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

As explained in commit 6ea529a2037c ("percpu: make embedding first chunk
allocator check vmalloc space size"), the embedding first chunk allocator
needs the vmalloc space to be larger than the maximum distance between
units which are grouped into NUMA nodes.

On a very sparse NUMA configurations and a small vmalloc area (for example,
it is 64GB in sv39), the allocation of dynamic percpu data in the vmalloc
area could fail.

So provide the pcpu page allocator as a fallback in case we fall into
such a sparse configuration (which happened in arm64 as shown by
commit 09cea6195073 ("arm64: support page mapping percpu first chunk
allocator")).

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/Kconfig         | 2 ++
 arch/riscv/mm/kasan_init.c | 8 ++++++++
 2 files changed, 10 insertions(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 5b1e61aca6cf..7b82d8301e42 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -416,7 +416,9 @@ config NUMA
 	depends on SMP && MMU
 	select ARCH_SUPPORTS_NUMA_BALANCING
 	select GENERIC_ARCH_NUMA
+	select HAVE_SETUP_PER_CPU_AREA
 	select NEED_PER_CPU_EMBED_FIRST_CHUNK
+	select NEED_PER_CPU_PAGE_FIRST_CHUNK
 	select OF_NUMA
 	select USE_PERCPU_NUMA_NODE_ID
 	help
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 5e39dcf23fdb..4c9a2c527f08 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -438,6 +438,14 @@ static void __init kasan_shallow_populate(void *start, void *end)
 	kasan_shallow_populate_pgd(vaddr, vend);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
+{
+	kasan_populate(kasan_mem_to_shadow(start),
+		       kasan_mem_to_shadow(start + size));
+}
+#endif
+
 static void __init create_tmp_mapping(void)
 {
 	void *ptr;
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231110140721.114235-3-alexghiti%40rivosinc.com.
