Return-Path: <kasan-dev+bncBDAOJ6534YNBBCWQ6XBAMGQE2H6QBOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DF3FAEA294
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:30 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-451d2037f1esf7052565e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951947; cv=pass;
        d=google.com; s=arc-20240605;
        b=dUrRMsYYGB60xsREyDGYsTqdCR5kxOpC+ePDkA544ob9xKWpVyFaVR5RWS7+CwfTqP
         qF8CVoJbBHRZDa6CLdyaYfxTVlwWe6ibWjwfmp4jJl6/po+CtCYSrjm5ib7FwffkYfJ2
         asMiMVsnsUERadaU1DhO5l1kWIIXoloI7+8z2TLbyoVrpIIlyGweUklu41aQmHk5bXo5
         eZHrcAiphFOtOH6CwQmOFrdrCtKAOtrDlGM+Cui407JKDoY7fnG7OgBOKbpLmowjmcF4
         7Sw22jn6+r2YYxf0a+4CpGHAkSgE3ywHaTGvAoxXkVrjRUqEvW/Yy3+QMApCV+8iDKu+
         zn4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=8C60KD/54o8fTkBAzEAKPOBdb0G4vRVw06qzfvfbS+Q=;
        fh=m29RtkzzGPg+htvoV5WJVGvdlB7n+cA5ucrQcW/lpVg=;
        b=lv2xxwnDKqzThow3L5Ujn52A2NwdYpXqizSlul5tl4gwrmN0RxFlcBc+G0rXh/NRTV
         XAjRagaLiwiZbFacINreFok67P+YIvLh4SJFmlRXJWadf3yx83FQluzT/YMPHxhD/hUY
         am7jcJ0GL41pZUWX0J9ra/XLpwdaI+AAeGkRQeG6Hfe7Bm7rhWCnzRNeJTvqkFFo14X8
         WF5uHbMOZIo1fyegpoOJYm70yVj3Mj0ZgZmgQngHto6OteOF7o0vr59Z6T54BNo5485n
         rZZn1SWQCcyGHsPK+FMgPcLeEvOhIvM0XVYk/XPaUomUNAzuMe+hjpGOpSUiGL/SbuxL
         O6Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XsmvSQqU;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951947; x=1751556747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8C60KD/54o8fTkBAzEAKPOBdb0G4vRVw06qzfvfbS+Q=;
        b=xy739lPwK1HJQ/lXuRifLa2RE7CIW88bquCsT/7KC7LIlndBCFucSTkaIYMX/l7XqD
         rf2Vf7Rlk6XuoyAm6/LruU5IcTuzIsT7hPmwOYAppbu8SVlUmJLSo0TdCaEBQd9W1YQY
         U/MwsAERgUpRsnAMXYbKRdFIoicTE6Ge/m0uu+xKXM7XYSU8W4IlGOcBYmsZ2Vs9waeT
         XzmkgvTD4xsu001JiY3PFHMwPlnyh9tT5UlPCE2241FZjxxKUKm58iKinGzUvPC5iSDR
         6Bgb6Zl9hS7gTt9F0vpM8jNWmDtGcpvK2dJb/8Z2Ew4TcLzGbKC9MRUN4n5qAPhEcZQ/
         o67g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951947; x=1751556747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=8C60KD/54o8fTkBAzEAKPOBdb0G4vRVw06qzfvfbS+Q=;
        b=R8TYnE3HIZfc5dPa/L4PA4fJdLX8Fy86SGawC0VZCkSQnU5BGXHQLlkl+dHaDmbEr2
         M463hgnUZdGHNhkGgEjOCM6E6FmGaG1/s6ziVZbtZ8kDzHwV59vqX+dxjQ0GhYuHt3Xg
         IkhTPxleb1fzQdY6OdTTzeg27gfqI9Q8igCXA8FJ/RsjUJk5YApTOQnqAG04c2JnG7FI
         dfTB5BTc+u9/pz8q3kZAAebHB3AriMammLws+XVvBGykC3oPw2IEp978g56FTqO+Ca90
         AxwEwxvzzVweeFCUaXkv6cmHyDXYHjn4QxsBmtmL/v0q/BfFGq6dHvZbAy4f02BcqS7D
         3xJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951947; x=1751556747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8C60KD/54o8fTkBAzEAKPOBdb0G4vRVw06qzfvfbS+Q=;
        b=DqxWTk8YqED0evj3NcTKYHFAGxep2eGZeLW/eNRyEzcaLs7X/+O71yEl+9vT9EPf+s
         0243lFUsSQPCw3vAUbd79FGub+HXLVrV7Vc49ZjM1rgtYWDERLi1MAVBDjJJBhLUWkwT
         DFhBaAG/FTS7DcqjIkWh1A0Miot/RKmeHshLxwywFGZDH4ucOHB7/n8FQj+hi36w44FH
         x0nqcMzkgScabIlac5FWZLS+yx6jPsreH4+YFgqy7y7/zSzxjJ6khX8DA7eaFwgz58oO
         Klt27pwqZdYAABu1HEAsXGQmqke8WXHxbbwe5mzYargQzU9XAGC/s9j5kDu73J7Bw5nJ
         C0GQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgUZxO4wuROChr4mglD28jC9EdzutGT9qqzm1/k3iSZgvkgUQOMnFPcn01+rENejD+T1gg7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx4LUsqwdGeAFGb2xKw++KV1DtFznu16Hvs0p72SugKDuCZccaS
	Y4kTeUsgyp87C4dWFoMZbvtH9vNj/jyWYFiG/ZVXiZrBZ78qPITNNnGT
X-Google-Smtp-Source: AGHT+IFOGx9v6aT+TD8X4ULkWtIt8LjhE67oKfoStmhgWP36aAxkJOiOlvdaWvNBc9+zDViy8QjSYQ==
X-Received: by 2002:a05:600c:8710:b0:445:1984:247d with SMTP id 5b1f17b1804b1-4538e3ae3ffmr8341015e9.7.1750951946730;
        Thu, 26 Jun 2025 08:32:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeXIG9S1oiacm5mgX+UAa6EwjOWD9gTE4i8JYCt7R0QMw==
Received: by 2002:a05:600c:4e53:b0:43d:1776:2ebe with SMTP id
 5b1f17b1804b1-45388ab58cbls7686785e9.2.-pod-prod-08-eu; Thu, 26 Jun 2025
 08:32:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsOdzWWUXwD3jlHPK0VgRTVywQhVLhmEio/B9+vLSJ1XVVLwsxIC/do8xvqjH42RsnIE+0n25dgPg=@googlegroups.com
X-Received: by 2002:a05:600c:8283:b0:442:e03b:589d with SMTP id 5b1f17b1804b1-45381b132f7mr74564685e9.24.1750951944208;
        Thu, 26 Jun 2025 08:32:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951944; cv=none;
        d=google.com; s=arc-20240605;
        b=PgW3yPaWqZjYWZaCTH5FYBnhVHo8UMIC+8EAupq0uLCAvudFnZkJBOcfCi0XkPkO7Q
         x4Ws4akedh6jwDjvjjXyPgwm/K0schDvkcOy6ySMCxpc7jm5LE4SzPwH37pksN4QS4Vy
         IumwWNN18ospsKgiAc7QQUwPcZo4+Hpp25fbtoEehdRsYqkxGSMsJnMmRfcg2EBTTemP
         AuyiRW0UR20YzIddd0HZ9MCNTh5Cy93ow5sCBy5gKkDODQhYJnFw1LuqRdeavXTGm440
         jtWlMQyDhmZlA/9HGuLTZIF6P+eSXOQvmBAZdu1v53b+Ly3OKhojf/V6dfi0S6M4sccx
         h8jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PCoYbCl3wZIeXCSyY3ZNY+HzBteHxI7NOqzCSDqwFag=;
        fh=YXGsQDin00aEr0iful84mjzFb9LEaSJb/3ySLVZwiF4=;
        b=CMeEkn9+MHisku4+JxcDVT6/PzQ79Ih3Ymmwjq9+Iy4bDu75Zgvu6tnTcqmWUdue/I
         VIgjp9E6DhDyqt8jAIQjh12G3VFH8L8Yw8o5d9GpeIJTeQAGOT3EOjioluQRHbPLOd5R
         z9a+Y/VDoMt4RiAH9Lve7LfbTwHOmc69Z3Dg1g+rW7DpgY/ek0+YHRWM1u74W+M55Kaa
         C52XLIs4QAGF6l1LRQGLPk7xfcPdSMTBcUXdMe31nvPZBtAO9hThV5nfkGvtWhxbOxXf
         bPZHdDxNf8jpNxwQtjKQ6ybBt+peHgqYVuEcJfi2+BWA/HAzamGHVALLTZnQGxRP/Lyv
         tb7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XsmvSQqU;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fcff4dsi1058105e9.0.2025.06.26.08.32.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-32b78b5aa39so11778521fa.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWijR5VBTkd1TwYvLXvYaNFRpm+82kbvYW2xre0MOavw/0zYcSRdh/PiSBIbSE88ppKcRBIRWCrQmM=@googlegroups.com
X-Gm-Gg: ASbGncv+gKXRjca6jWmrsvMQXhaUrtIQlA0hzj4MPd8dswUpUvIhYHrwEgio7ox5krg
	LUS6hsTcNVVse6jpvHeb7uCBne9Ba7V6mUBrQVB+a36qH+EI7ngUZBaxyX0NYtGdotrspP6RFxz
	cJOmji6BSS7KiugUoRIPfg4upTcplLc/KGkPboeBvJRdUeZFHko3knjPNTa+Y7XQKDrmVoiVEZl
	luxV/Gp/aJiiU/5GYmJlTDmeyerh/Zm2wHpex0kkORmslxUenhFJbJq1xXmylI7gyjsJJi1X7vp
	ZERb5iaH52gO1B3gtLjoSDjAd4i9IHZocL4Zo+sHCpuqa2QMm3Qe8pETC3oxr4/jPsztShaXzou
	LVvqKxvvaC77A998hoHu6me6fXcNkpbz+6Z8vqnXa
X-Received: by 2002:a05:6512:3da2:b0:553:26a7:70ec with SMTP id 2adb3069b0e04-5550b79db9cmr1980e87.0.1750951943188;
        Thu, 26 Jun 2025 08:32:23 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:22 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 03/11] kasan/arm: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:39 +0500
Message-Id: <20250626153147.145312-4-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XsmvSQqU;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which enables the static flag to mark KASAN
initialized in CONFIG_KASAN_GENERIC mode, otherwise it's an inline stub.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f70313..c6625e808bf 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -300,6 +300,6 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
-	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-4-snovitoll%40gmail.com.
