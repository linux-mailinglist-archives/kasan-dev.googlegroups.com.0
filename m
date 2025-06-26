Return-Path: <kasan-dev+bncBDAOJ6534YNBBJGQ6XBAMGQEWNSOBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 09E99AEA2A2
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:56 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55220256289sf608916e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951973; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hr/D4Zsbn6sDv51yu7VuYWWNKgFgnFUAHutxTdTasgaIrOdFSOqtX5XvvOpVFXJtLr
         TbX5lCD4j95fCUj9CYIYJTlli0fJgmYYpjbBsd0DxNUsGKcX054mqnSvBvf0/gq0wN+6
         oE8lEs9dykzxDJ238OOD4AKMVQw1QFxvwCqwlRAdbmk9jCfDmi4zYI0NjA0q8oNoNOid
         exwb2oHg8n0ugKehzi6HcvzELlksiA2RE/iurPR9YjpO9TrWC+UMNa/hklkHLLwEVzXX
         AeaHCvzvWm3CoXC9R1Mu/q8jBeQ9cNHJOsEGPJyhzjxyCHDiYaGgzl7G7s7YGNmOdzRZ
         7N/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=j0QCUPaO4XPGsBZTd8hnLulIJFC9axIDHcEBaz25NMk=;
        fh=ycqMps5BvaR/cpz0BATgvMiQp9mB8wxF5XBiK/p4fE8=;
        b=COpCcFJSrGTH2bJ/g3b+oXrULBqZWQdoSTVPUgCfSkH6aYNrS8bKTI4GTK2j4BNX/o
         PrsqJ4HBDnmgjHGDWBdFZLNnAH+//UqkbZY4KmI3yyfGrUVI8xipg8ntc6G37jPpH3oF
         z+G0L6BytLMkEhMzHRUdWfAQ0IHzel52NrIZgIy2q34REeYQ4rlRGEwtplGmqGloF8Cy
         6bH0TxO41TVxHRNdrGtXLO4MNLOEpWmlM4E2sDBncTivi4SQymcvvOy+HRcdAhwnDGr7
         xY47kzpMtPdGBSqyk3hik4ZinV2FbL58FIOz4gYBXvJoo/7Wn/lJYkB3SOSprzx+DM/Z
         13fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A/GrKNmv";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951973; x=1751556773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j0QCUPaO4XPGsBZTd8hnLulIJFC9axIDHcEBaz25NMk=;
        b=gY5yvHP46W2nB3cbDJDArUNiyQYH4wB/SqQdHjEB+kW9oAxghAC9bWj1n0w57qBFgi
         48H0o/SDvelpmDyWIDe/jLUPyS1wR73HOx82YgLsaZjxiIn6c/iAaKB/jBZDqnaa05vS
         kt6Wr/2DIpQwQ/UuOSwxAYZZaupS6AqgT98ggKIPxFUkBxbdXS50nkDL404vSsPCJ+W5
         46/7QKxw6ZjN7jO0gelYn/7atPqlLsDsDwBAO5gek3WwBAZe25bCGu1j16q/YMRgJW4k
         j81TCUWiNBFgM6Px4gYCvGOWNWiwBWb/nlE0bNxPzWzlIhgozTcQmK1B8b1vAdaXuSge
         oO5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951973; x=1751556773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=j0QCUPaO4XPGsBZTd8hnLulIJFC9axIDHcEBaz25NMk=;
        b=XRTPrsoljiF9kG2ParEIo304eQaPgr6xHNSvYskbuUqOh3vawiPgSPICc4JMaHMXhN
         v/E87zJCZ0OWGLUGJuF/7WiFimlZyPN3PG1NbjfaSzplKDnj8pPOnZh7mQnLuWgi8FOn
         T0wAyzOwBOnLhZO1o49IapUzqNrWtL0UKjnA3rrdmmNBeFn6illTGdLPAg25truZIlPz
         GPcnp0fW2ClR1R+8uHpJl9jvWvzQ5Bi2BdquIHdbsozA8yQ48pPxtU8aYPoxm+H62vPF
         ACx0eGflII6hOAnOj3JRbl8ui2Shcm+MDDBtUwPz/2IzEQDYc9/1gac6hnl3aEbKZTG3
         alYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951973; x=1751556773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j0QCUPaO4XPGsBZTd8hnLulIJFC9axIDHcEBaz25NMk=;
        b=F/heqPzVrmKb9l3vINsD0kYvhhoR2g7yr2GA7kxCegMORQlA1tbfVTLRsoffKhrO+H
         f6M9Z/QcLCGTKGCpyTTcn7NcjB5gvpRzxKI4taQb6af2sMml1dEDkNwpKmvHXUuAiH7d
         1UzSY99d41wVQml6wo/mZ3F+Ck9HFnw9qB3k2Xc2LP/scWpaNMvT3rEh7Ht5HJSsEWzr
         iJjMz2a8qMvg6yUbOrNEcD1DflGNmlb4SdijeqJAVcHo1cVMI0247n5Bmwqj9Dm7bsE2
         Z1wmNw9KVh/6YXiuC2s3DKk50zG6HEQ3+PmiRRP6WzTHKWZ/L6dtI0jm3vhNgavRg4KN
         aD5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdvpRz8VjKx+Z/ST7KffweUZGogUMexnUihEcU9uWyEF0Z8Y7Q6u0GPBh27JNpv6BaPh5SpA==@lfdr.de
X-Gm-Message-State: AOJu0YzZtdVDkz5VCYBaJYWPhpIOobEpB7CxBiUlXVW5Da5Aak5XL5ro
	2PwBjl7wiJ5QLfYMQS5njUALyYDvvyfmmPz+4U0U24FgYbyChJVdkuvd
X-Google-Smtp-Source: AGHT+IGUODKXLIqQJyFGvjk5KG+5Q5ceIpeitAKb6xsmwAJYgWCDeAsF36AwAS8s5/5tzBzFTKMsEQ==
X-Received: by 2002:a05:6512:1386:b0:553:aadf:b0c4 with SMTP id 2adb3069b0e04-554fdcc4cf8mr2309251e87.11.1750951972775;
        Thu, 26 Jun 2025 08:32:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIGZh/NDOaq78JJsOPbWynKN/ACDGVS3WIizhMihR38A==
Received: by 2002:a05:6512:6088:b0:553:67a9:4aa1 with SMTP id
 2adb3069b0e04-55502e0649els390076e87.1.-pod-prod-09-eu; Thu, 26 Jun 2025
 08:32:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMr63QdWLVSEfekLKB9bTulbOWjXIPdzngIXoA6mNJpDzDQxUSTELckdMw9SiQsZHn0nBzVUXHLTQ=@googlegroups.com
X-Received: by 2002:a05:6512:3ba6:b0:553:2ed2:15b4 with SMTP id 2adb3069b0e04-554fdf66a6amr2248851e87.57.1750951970295;
        Thu, 26 Jun 2025 08:32:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951970; cv=none;
        d=google.com; s=arc-20240605;
        b=izuZvcwBV68nqsU8kynmyyvId5KppZh3n6GvF+Mtxv1rMRRiR98tfOGrtaGs+LrywO
         omKy+Ol1To3jpFf1eVviAI4EYYf4d8H7fJxZAPKLhq6Yb7gH/Ynw2l6ZFemgHEDV4UlA
         oFFAQNwO5ypFrYZzh2eKymnN+xq9y6sspGUebU0tEk+IH+9GoFfAGVO+uHA4awwpY/CJ
         +Hx7EYLg4FJ73LB0yKQprC4kePKaw0ReKPGSLqAxrS/g4RUdz+ybTaU4xgUQ3W+ibwkU
         Tfvo5BV2nJHMU6sFEbRvd6bTWaYJVJk4MFPL1GrA0Jw8IPa/l632RxwlFWnokR82VyOd
         Md7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iNdRW1IbQwaJLK3IU9ZGilulsvtFwP6FJhql802bOZE=;
        fh=nsO1VQowxkklpFXZPmISQB5HtCu9RBqDFjM8nYaKoCg=;
        b=LBoQwkqDMO/4Iq5SD9wQaybZ2g9ZgtRvk23ZvI9X+wmuzSzesKYA8fOJIcb53Lwq4R
         ftNngwdAJCGua5We7XpaQdSQ4e5W6gNuqRPN4xzp1nrSRaSjSQ/SGWmSfyDKqtpOCUMk
         QFtD0smwaANKCQlaVBwqMQHbVAY4HzJH+WR9zDktDHTMWtK8/cjfTa+nbe2I56Ipl2pM
         rRkPqPD9aBMCYbKcWzF8E5zTy/9LnvNJUIgmIGcP3OKjnQcMZd3TQJ+sptI4ZJm5NIap
         1dhRF9CkgTjDOkWCmj3w0wmC0w92bYqMjWYfXokWPK/Uh9dTJhR3yK4cfK8/8cN4FaJj
         hZog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A/GrKNmv";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2e927d8si419531fa.4.2025.06.26.08.32.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-555024588b1so1399860e87.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJgijJwSF3TWFckJeUqN21M8JA4BJMCeiePsJDqTSpKZd+E7GGl6bP7t5bwR+78dAOvJoeYZDhMOM=@googlegroups.com
X-Gm-Gg: ASbGncvrMczsmDNXqTIWSiBPqiVoN/JEjBW2TVnIGNLRYrmf+GCKF+L5A544LpbNzF/
	nVFE445bV1cwnU0fia9XQXi6HEnEOZmbA/YocWDL4P0mVVRa+D2ezd3cYTVsp+yTSf9Xhb4wKRy
	d/flEeLHnmlHxV3nrz2WY2DGYPjybgJgl1SyRWJ4jOGJo37BsamM9Optst90fr9N6/Ztl/TEG+H
	isfqJiFn+MXvxUTmQfZ+aAleL6zDUfxczXP6JEOsPS4hWktmfkiuUy5OnxlIIa4gfw9nTC8/VrK
	lh6EsbHCS0f9wPi80sPKZrwL52L+/+lQ0cmGnTCtCA3ZxN/9NVzCYB1oRKZgYM6GPS2AiDxcXLR
	bsIjPoGFJJ5FDrl0tQ2qWRqzFXmFvZQ==
X-Received: by 2002:a05:6512:3d8d:b0:553:d637:1e96 with SMTP id 2adb3069b0e04-554fdd1d556mr3088387e87.31.1750951969599;
        Thu, 26 Jun 2025 08:32:49 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:49 -0700 (PDT)
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
Subject: [PATCH v2 07/11] kasan/x86: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:43 +0500
Message-Id: <20250626153147.145312-8-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="A/GrKNmv";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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

Call kasan_init_generic() which enables the static flag
to mark generic KASAN initialized, otherwise it's an inline stub.
Also prints the banner from the single place.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/mm/kasan_init_64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d21..998b6010d6d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-8-snovitoll%40gmail.com.
