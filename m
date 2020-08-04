Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAVPUX4QKGQEVHMMV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DDFEC23BA88
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:41:39 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 7sf49973851ybl.5
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:41:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596544898; cv=pass;
        d=google.com; s=arc-20160816;
        b=0fz4cUYdou8hrHMjt3lCcHAcUC6Jr92M8c1EfLSfk10X77cXJvcb5EfOv62QoPkm4s
         chgfJGjt4TYmn5StDtmPbpE+swdO1ux9azyDUx8aud3bJbbSO4Y3Aq5vWuyghHXMDcz/
         P4yj5RuOVO3Ogz/n/iz3GBUKCwQ4MXjku4II68lDnos4ARBodkTvMFPMPCXl/LtSa67L
         fBFV9ZN9oeKBofzVqouP/zZezUOzoYzqxRmNY6WihV+zkxafnEF2IQHa3HSlFV/Bbbfj
         XGDz6fVAARh8PyCObFNuqtbEVpXKquQ6keQT9yOsnRdis+8C+mgIyfzXkLI8whUJLMar
         1k9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MeiHP7IJswXrzI74gqOhhzYWuPGuDMfnGkz5Gdtmgts=;
        b=ZeUgLa758EApdWs8V8GWgo7Zhgy8P7qXHD8I56pnnUlXcHVqfRJWF7EA/sK+yQEo2l
         OyBLklyYBKqNG1C34nTNqlTzC4N3YzjaWoLKQ4CajIKe/ye7IORqcOcj0JPZXiMZklQN
         3/AbRL0vBfYxyiXP9T3MrTBX9xhr7Lj0I1uHhlsFBXxoPf5dI2S2dAqN/9/4DKdnNDXJ
         l5+k4ciX8iUc7b+osl5SvcgJ9f9EdLZUopHdht6+7cnaxG/xmCidYOmbea65CMgwjyPJ
         S25CU8TmRBLmrEvfd7SzRrFU78CxHcqUvkyezwP88QmXaEVSgF8eKKDAUpNkPmwTkthH
         4Llw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=El9eCMgZ;
       spf=pass (google.com: domain of 3glcpxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3glcpXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MeiHP7IJswXrzI74gqOhhzYWuPGuDMfnGkz5Gdtmgts=;
        b=SFEwOoxP0bYGe7nc/JDs8xSB584N3xlcDMARhHwLIlycXaRQ/U4nm+cVXi+3O+otCN
         qvAl7y6KpdhWecBnv280sI9Cl2J7tmwruN0eo0PjQWGAXYxxTprUusea96q8K9x1vFNw
         OFdsw2zU0UNhlgiZ9FIaOdhryFQ+Twk6ymOUhXZA9FyddpqOa4HOLTSGAEVkJJneg3ER
         DBohSsK99xl+M3jvqbKpfX1icwRNYywOuv+doOyK/o91wzZrUA8xjTa74yzfhluMN/l4
         9eaFWOhn52iOHMAHu3YstCfFwEsjTaI1m9R7R/zr6nXzkZUMlZg7viDoW3h4Qo7xt8um
         FUwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MeiHP7IJswXrzI74gqOhhzYWuPGuDMfnGkz5Gdtmgts=;
        b=fW1LUxz5ugj+9GpU102JsoTD30XBr1q9AYD+qoJRuU3ctncYCraDVd6XYdLD4A4g3k
         DJma72U3bsa10PF29FMweAl/QmjvCHm3ym8ssPTFaz1wUc+HMYSxp/IwFToTyaabz3hw
         MzbhHxBhNv+wMvkLtI60JGhy6Y8TN6Rt1PKRi+03yiuouVaO8fp9UxzftwQNU9zaglXN
         fcXjpezDrYrq4g4t+HSSGI7gnXTXszgB5xbZKeJEPUNdQVA8E6fesToKxDljDFhbj0I9
         LEJU/zp3j9rChVkoSeEmKIvmJ+n+za9ZDa4UTuJhZdIZs8Ru9ML5Pn8hMH6IgBJRsTLo
         njzw==
X-Gm-Message-State: AOAM532/ohJ1tsJF7hpn4f7MsxTJb3DIbW3EI09uXZe2TiMijV5yisnz
	I/BsLUVO5T3DT+X1WUV3agQ=
X-Google-Smtp-Source: ABdhPJyCi/Y+IOVCk1HFnJOPMlNpmlNCRMzdyfF+LaT3B855NmvDaGHKAuCJIavrbC5ef/UANyxr6Q==
X-Received: by 2002:a25:c004:: with SMTP id c4mr35974019ybf.475.1596544898775;
        Tue, 04 Aug 2020 05:41:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6cc1:: with SMTP id h184ls1101266ybc.4.gmail; Tue, 04
 Aug 2020 05:41:38 -0700 (PDT)
X-Received: by 2002:a25:c004:: with SMTP id c4mr35973987ybf.475.1596544898495;
        Tue, 04 Aug 2020 05:41:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596544898; cv=none;
        d=google.com; s=arc-20160816;
        b=ohLa4/Hho/3chJBoi627J8vVhYvJGycD8pd1qtpL2jyParGsMF+K/ji+1wDdyODEue
         dWkQYU8+JaUnHiwJmDml/BgWGWYRoAAm45SwDajnRq8c7wEAkTFbyhfBiCy4hKXHj4MM
         znQESXL60n7KzDDoTQ3ZYr+KQKGXKEwKnjS+sdlHqhFX4q/uKzRQXDpmkFGikBMJ8zZO
         aa71kzof8TbMxYuZVf9ggQ8hppvG2jOda7APOA2L8qZE02cnrgZolPdLP7jB2dTEUifH
         CXeuuHg7/5Peit+Av2eauqQhPzLjFdaIPShsGE3lbgBwjeI/MahS44ecn5vlcTtqSuBq
         f4Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=MkWKUi7xJlcxy+e8OWBoJNl1OXW3h1d9K35k1It603c=;
        b=vvxrJIhf46W09BCobMgNXHuakGi3YRu5kHI1imIpPvAgCYJ7D8BsUBtJinKCy1ObtW
         3tAsgGiVsGs163CjHfhmlHTY0IxqzoIGRKcUTxRFNHXfbdqHFOKKi0eMana03msYguSl
         9HMlXfdQ+GoEnQBn/yShCi/5/5Mw0Pi9qvz/FFCmdGl9GYLc1SQGI/W31nA1UFptZ5Kd
         FQdk1jc/Uc0Qphoa6FixDmShpWlXhlz1YrvhZZeyWLrEqvMzarFt+aqXG9BhEnGA1bhI
         VPnmOkTYIhDyHotD/iWWJeJMU2m8BnKy8ThJ0H+YXSw8CYHtRi5Rf9n0mnXpYiOAMTKK
         EGPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=El9eCMgZ;
       spf=pass (google.com: domain of 3glcpxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3glcpXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id i144si1054865yba.4.2020.08.04.05.41.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:41:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3glcpxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x190so28433614qke.16
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:41:38 -0700 (PDT)
X-Received: by 2002:ad4:4152:: with SMTP id z18mr22181844qvp.42.1596544898043;
 Tue, 04 Aug 2020 05:41:38 -0700 (PDT)
Date: Tue,  4 Aug 2020 14:41:25 +0200
In-Reply-To: <cover.1596544734.git.andreyknvl@google.com>
Message-Id: <6514652d3a32d3ed33d6eb5c91d0af63bf0d1a0c.1596544734.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v2 2/5] efi: provide empty efi_enter_virtual_mode implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=El9eCMgZ;       spf=pass
 (google.com: domain of 3glcpxwokcdu1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3glcpXwoKCdU1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

When CONFIG_EFI is not enabled, we might get an undefined reference
to efi_enter_virtual_mode() error, if this efi_enabled() call isn't
inlined into start_kernel(). This happens in particular, if start_kernel()
is annodated with __no_sanitize_address.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/efi.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/efi.h b/include/linux/efi.h
index 05c47f857383..73db1ae04cef 100644
--- a/include/linux/efi.h
+++ b/include/linux/efi.h
@@ -606,7 +606,11 @@ extern void *efi_get_pal_addr (void);
 extern void efi_map_pal_code (void);
 extern void efi_memmap_walk (efi_freemem_callback_t callback, void *arg);
 extern void efi_gettimeofday (struct timespec64 *ts);
+#ifdef CONFIG_EFI
 extern void efi_enter_virtual_mode (void);	/* switch EFI to virtual mode, if possible */
+#else
+static inline void efi_enter_virtual_mode (void) {}
+#endif
 #ifdef CONFIG_X86
 extern efi_status_t efi_query_variable_store(u32 attributes,
 					     unsigned long size,
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6514652d3a32d3ed33d6eb5c91d0af63bf0d1a0c.1596544734.git.andreyknvl%40google.com.
