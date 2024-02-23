Return-Path: <kasan-dev+bncBCAP7WGUVIKBBQHA4SXAMGQE2VW6LBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 571848620D3
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 00:54:42 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5a04ee4c112sf761915eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 15:54:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708732481; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqaGtHVZGptVJoQJaeRbMBuzCVTYN8ZZTUZ2XaiZSeQMywC2jHUOAsDwr/mw49nVhX
         fbEhG0+fKm+UAKweTMkEvJk+f2OLdc5OKNOsCmabXitmepq+tQQL15zJoiG9lJ9hzI41
         oD3PtNztt3VkQTNjGsHW5YkMHkE4kafPokKTkaMKyU4h0AVZduWu9C/QA2lD7avSTuTo
         +45ZEf8ssXufCbzs4LttvJRNGOlzg58/3adyy1xVccYIp0pIobyRuHshTFtBqxJePRRQ
         bqJefxwxtyO2z+zXcXNITLEVROm3R1bgsQT/SHNMNXpzGKPpNBenVrqJmqB/6glDiTB3
         lqFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=C/4TVEVokkViSdL3139vurfCP9KWn+kz7IXoMsktxoU=;
        fh=34CHZXFaC4VuAB95VhhB4GMmPPMBm6Mczb4rgALc4ck=;
        b=VuDtu+IkkxBiKJVpFsWy71F7A4nHtZUD7EZ8FKZcNeYdRnRUvvuJSHHr4+PByBsSJK
         //ni+FkwNu0J9cxp2U7yWRcoJw3SEhQmQq6vFlrVSEQ0ymVmS86ZWo3F+E1Zv6IRaYkJ
         hGkRwI8mvKZeE1PC/qYj1NXtL8izl/7RtoB8g54L3nQ312+Sdc5gZw35lYcDs2JNqfMS
         YQLnrMk1Qn5/dpGtMXzCdYADfF0SJU7sgH2gkrCltKtwvj+0IodGVqxtj9pWCv8gBtTo
         CDesgtrlUk5l/bJ1iBV2SDOm86bTic5ADrTaCvizwRqsXSIoYBn8VeqUAc40i4qgydIn
         0ysg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708732481; x=1709337281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C/4TVEVokkViSdL3139vurfCP9KWn+kz7IXoMsktxoU=;
        b=VYzF5lYg+IEQBkWpwQzGtmffOv2XvrcBADEASrvXvmlXTo3dUo//B0PZfQ8U65ndfQ
         6rtWBGLvf9FZ3PKsrPrPc57+qlXi5lFPD4+tzk497kSVR/wnbHKP+C37EoEchwoqIRk1
         0D4VRF8I78wkIWZ5UVmApkWgcDmj3uHoMBNGGpvSb8+ankEa/p4abUWt3AXOTkzqNBMP
         Gy8AxhvrGDlC6AVlamK6XI+5XhRjRhKmo7BgdY/sOJu0vn2XxXmBs/O+qw8PSUC2bzP9
         5LJ1Qa3WuLKo47SPpLLBXD0P/SSPaNeL3JQBDeoJmAH5ofiV7y0mBJGyMM0qebVs+U8T
         G7Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708732481; x=1709337281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C/4TVEVokkViSdL3139vurfCP9KWn+kz7IXoMsktxoU=;
        b=SKf84oiO1DBK0zCZsN+59fC9Zn7UUiSApXwOA1aCdg+vfuqM8oZ+ZioYz/Nnt3doyy
         l3QrJPfcLDBeeCbo/GkTcW4mjjpgw5cGbNqMaM+aqWw3M/k5TImYmvsiK6m3g8kvLRWm
         n0RAAjMLJesYbZCpTIH/Fr1Oo3A+PPSHRa0Cas0gocVXkCMKMprZdWnS77iE1daLQ9Zk
         o9K9lZwcK9dKSRRsoai0w4hs3mXN6BJVSE3xD4bcYsMDPDImnZTic4lVRALxoLG6OMIa
         0pbwHyGE+dPn5/BMU7+8HDZSE6Rnafva30C+3B4gQHMwRZwNq54RJBF/+zW5oSMMff1y
         2LKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQ2lstKJYpai9IdiaYROyWNceFWBwdRm+Cd66IYhA6JyZeJLjvghoeu4niR79QBo/TKE3XEbVrXM4PxU73EhMpc1KP0ZCb4Q==
X-Gm-Message-State: AOJu0Yw3Pfji5O39BZqxCMcY6lJzsrGhq1+A8NYUaWCmAs8NY7WaeFdW
	9zdShOlvjISAoXL4tjiWnJk0VUkYQg6+X1UA+1Wzum7CYc2YD2UW
X-Google-Smtp-Source: AGHT+IH/tYEF65LnnDI0kJSIB43ksAdrFl84V25cqwt+BSUqhPkkGF8I++uDJMf85I8iHwOu9E1yJQ==
X-Received: by 2002:a05:6820:1ad5:b0:5a0:5ac0:e396 with SMTP id bu21-20020a0568201ad500b005a05ac0e396mr1042364oob.3.1708732480883;
        Fri, 23 Feb 2024 15:54:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d4:0:b0:598:6f4a:c095 with SMTP id e203-20020a4a55d4000000b005986f4ac095ls1203648oob.1.-pod-prod-09-us;
 Fri, 23 Feb 2024 15:54:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXw5j2g7MdK74tGkQEhmn/uD91ilyo3JUNVE1wog4P9zouQPwblUeG7Wx6+f4zsVTcmMDvduczEB3xotH8+DZ6nSopOOA/K1rNhAw==
X-Received: by 2002:a4a:3c01:0:b0:5a0:2a9:5747 with SMTP id d1-20020a4a3c01000000b005a002a95747mr1527168ooa.4.1708732479978;
        Fri, 23 Feb 2024 15:54:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708732479; cv=none;
        d=google.com; s=arc-20160816;
        b=oeOHASccEonHddGl6KtlK/OvwqWxI4v+YrAPOXtzMyX9vAQyqi4SemleJwH8yvjiTq
         os141M9/VvGD0H63v8cK6lpCQpffWQC8NZvvKU9ns61uiwX1csGH+VDxSUTWWsBZ7yiL
         WsHe/slL8PMPIzLSfZvCTKQuNHuH/nJVmvVuydvRU7n4Edz3Qp/dbyO57Jn3fi4d5KNk
         pOyAnWFt1Hz3EP/XZ0hzZWh/E2X1nif2Gk9p9kPVehHQ07sw24oDNiTIjf7TZgGlFt1c
         GZhY+tRIOEKJgcGv2wgnyPFIq2I5OwmMfzFL6pGYNK+PJUUfzvyrSz0gIxCbf2lgjT/X
         rOow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=XkDjNvtENO62VhSLqN5+leigVsfoPMITLL9pxVXC9Uk=;
        fh=4dClFmAx6Rx4KqFlA12ypLHRpanB2XjPqKYD+gyWp5s=;
        b=vC3obr99j4ngWg8ovc2S2yxs2Na3+IenQtf/BO9kXxWwZsaTVJ8goOxjaslpWEyvzI
         y8665fwJb6DSGgalDEinL/Eu3ZuM1uj39ME7bVUTnAZK/p1GYxVs+q0rrztC91jK3JkC
         hfpQ3Ghn3qk65KiZIjwTmYIZ6ex06RfMvcHiD2dU1Yo5tf99BkxlmhmcIwGiMsGnp5L0
         wU98JVn18mdl3OSzL4mPwHtOmAiN0wuv/XujQ7ljcqajx1RfEnFowDvI0ecShFZaafkP
         veTHn/UbW4twL3r+5gqs+kZUlfbsnqmeJC7AncNimKX7dO85V9BRu6wKfVNd+zVbNhaa
         FA4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id e196-20020a4a55cd000000b005a0554c5d86si6955oob.1.2024.02.23.15.54.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Feb 2024 15:54:39 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav113.sakura.ne.jp (fsav113.sakura.ne.jp [27.133.134.240])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41NNsIeZ081563;
	Sat, 24 Feb 2024 08:54:18 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav113.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav113.sakura.ne.jp);
 Sat, 24 Feb 2024 08:54:18 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav113.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41NNsH57081559
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 24 Feb 2024 08:54:17 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <678f31f8-5890-47fa-972e-df966aeb783d@I-love.SAKURA.ne.jp>
Date: Sat, 24 Feb 2024 08:54:16 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: [PATCH] x86: disable non-instrumented version of copy_page when KMSAN
 is enabled
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        the arch/x86 maintainers <x86@kernel.org>,
        "H. Peter Anvin" <hpa@zytor.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Yosry Ahmed
 <yosryahmed@google.com>,
        Nhat Pham <nphamcs@gmail.com>, Minchan Kim <minchan@kernel.org>,
        linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>,
        Mark-PK Tsai <mark-pk.tsai@mediatek.com>,
        Sergey Senozhatsky <senozhatsky@chromium.org>,
        Alexander Potapenko <glider@google.com>
References: <d041ca52-8e0b-48b3-9606-314ac2a53408@I-love.SAKURA.ne.jp>
 <20240223044356.GJ11472@google.com>
 <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
In-Reply-To: <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

I found that commit afb2d666d025 ("zsmalloc: use copy_page for full page
copy") caused KMSAN warning. We need to fallback to instrumented version
when KMSAN is enabled.

  [   50.030627][ T2974] BUG: KMSAN: use-after-free in obj_malloc+0x6cc/0x7b0

  [   50.165956][ T2974] Uninit was stored to memory at:
  [   50.170819][ T2974]  obj_malloc+0x70a/0x7b0

  [   50.328931][ T2974] Uninit was created at:
  [   50.341845][ T2974]  free_unref_page_prepare+0x130/0xfc0

Since the destination page likely already holds previously written value
(i.e. KMSAN considers that the page was already initialized), whether to
globally enforce an instrumented version when KMSAN is enabled might be
questionable.

But since finding why KMSAN considers that value is not initialized is
difficult (developers tend to choose optimized version without knowing
KMSAN), let's choose human-friendly version. That is, since
arch/x86/include/asm/page_32.h implements copy_page() using memcpy(), let
arch/x86/include/asm/page_64.h implement copy_page() using memcpy() when
KMSAN is enabled.

Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
 arch/x86/include/asm/page_64.h | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index cc6b8e087192..f13bba3a9dab 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -58,7 +58,16 @@ static inline void clear_page(void *page)
 			   : "cc", "memory", "rax", "rcx");
 }
 
+#ifdef CONFIG_KMSAN
+/* Use of non-instrumented assembly version confuses KMSAN. */
+void *memcpy(void *to, const void *from, __kernel_size_t len);
+static inline void copy_page(void *to, void *from)
+{
+	memcpy(to, from, PAGE_SIZE);
+}
+#else
 void copy_page(void *to, void *from);
+#endif
 
 #ifdef CONFIG_X86_5LEVEL
 /*
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/678f31f8-5890-47fa-972e-df966aeb783d%40I-love.SAKURA.ne.jp.
