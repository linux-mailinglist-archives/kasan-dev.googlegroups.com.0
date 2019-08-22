Return-Path: <kasan-dev+bncBC5L5P75YUERBRXX7LVAKGQEASKARQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF615998A1
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 17:59:02 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id b20sf1129976ljj.17
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 08:59:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566489542; cv=pass;
        d=google.com; s=arc-20160816;
        b=xr1Df1neEAOwiXh1bcyzRdHAZ42v+ic7utxHNqiWWcmsIc89FiTXnHkvm/jq4T+ZEO
         +XX12NpWdO3A5mfg+RJBBNVC8gfVJTnFPGWdFMYMoNFqiMgXxDsO0sKuF4sO808VFSBP
         2Rwk0FiVMkxw+/B0v3YdxRpzG/p/rZQO+NmywuMaFuQRYBwXlKvDVIx7TMp+trAWWzs6
         fPAVQdMCqlFkqpjZJ85ei3PbGCsC5GWL+HL5Iqj+q8d1REUi/jjv2zInx6U6jl9BvHsp
         suglAc46MODvAkxY0tJE1sekCiscqrEpd85MuyLbPhbA4JTt/s6mSocfdzjuhPABe3yS
         rtMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature;
        bh=eNIAntC0gMXet4J4sWfLpPhLTxysON2M/ggNB0lgjdg=;
        b=TBISDLSBO2zAnPqJI/ZNnRV9BfEkW1uLB+q2oaFbxMdl75+JlNGkMm86/SpJrGos66
         0gHtzSWiUKjiB2dY2vx9rL6+wtsREugnpJsrN80fwAJf+7W+BorMNn/9kVWx0wpz2uTV
         KXcfT5QTSpCDSZt+ryYgAD3FMhIOdaekwRirOkgl4vR+7KqKrOEC74K/E4CN+rSOrdSM
         2yiHqdUJXFY+4olq1HvcPv/jCY/Cjxtju8E3E98uZ1eHNpEbQGCSZludY/iO27BmyNk7
         ovkUA2aHWgRMYLwPa7KNtixaU2IiqTxul5+lI/TwII689lTxJDAD0cU1mNXAAI4vcTA6
         DrsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eNIAntC0gMXet4J4sWfLpPhLTxysON2M/ggNB0lgjdg=;
        b=tK0lE1TCgIG+wsjSkY20DmLs5G5D8kRtR1tk2+e53+FmtOHq7S96lBkZOZlUIkcJiE
         apswW+dnfDq1dJeiNYMDXx7X2Odm+T7WxmX63Zlhxo7VphKe5vSCTanXE363YdiHJBDg
         aRfmexYHkb4GZZxPdEJeiX8UQ7me/MaHx6fSBPZxF7ip24nm0wteFw6NFEnq7Dk4RPEP
         2t/1kKUvWbf8CEdf9AojOCFqfZZFhrU+X9YPR5NmNnWzABJWzljAPIHYrBvGOl4oKsb5
         6n6D/FDV3XBLMR3GQKDNpE4PJ15KZWaTmfrLvslfJkueYJvWRz61C0zZDsl4/8ZdMmiU
         5IdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eNIAntC0gMXet4J4sWfLpPhLTxysON2M/ggNB0lgjdg=;
        b=UeYPwcA3vnrSHOBKGF1VUhncAtE+TKah3KqACyi69VgutvS5aV9/ttYkNaAnqHZ/sb
         A0BnmyJsmi7YWjshRBsROVwvtSxBHF9BgLpL/ZvtN+1K/Ebnx0Aa60kJjKX2NzTWE6RI
         WhDaN2FTqOfvnuyJJdQzptodPwsQy8YmZSEdj65lXP8gTo7MJxwmiekkKysLL1FmhIxI
         UY6f7h4pUgz1YGZDA0MY3Gcw3eMn8RhHNxm/mPAXP4agiaBAEBZw1B1kZfxebAHmedZT
         5OD2OICLT7h6De6GYnKZneIYiddoWMhn2WNiO48IsXileHWrgY+3hbAb4pH8RRc6upUB
         Xciw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqNO24JbCU00CoNDVeCTgxdJ4omu7Uln56BPPlb+mwNOU8mL6B
	IQp7nwWkAl4s6chzlNBTpqc=
X-Google-Smtp-Source: APXvYqxKQnFiG5Aeg58csM0mHhGPzIxcSiIz8CK8iaSYlDd16PMHn/L9BUv+1F4Nm9FS/NROCZXyrQ==
X-Received: by 2002:a05:651c:1125:: with SMTP id e5mr82730ljo.160.1566489542519;
        Thu, 22 Aug 2019 08:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:67:: with SMTP id i7ls605804lfo.4.gmail; Thu, 22
 Aug 2019 08:59:02 -0700 (PDT)
X-Received: by 2002:a19:ed11:: with SMTP id y17mr22039431lfy.141.1566489542009;
        Thu, 22 Aug 2019 08:59:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566489542; cv=none;
        d=google.com; s=arc-20160816;
        b=lSXd/A3Dy6VLKS1BfONX9NZA92Jo9Qc0YPHQ1kz//TBJTH6Rj0Ta6eQcWSHke0RKA9
         G+RGnrOWIjpvZ3fNGTpGATiBMbFCGpMGaNCotj77/ZD/YhYnETw7M4aZpkYRMYm0+Sm7
         pNHQu1m44ih87q1U2XLPQQNoSLtNDWkNlzo9xQmiYz3PgcyF2H6Gl64L3k1+5Ul6jfRx
         m7NGI+kRYwGm91mieRLu4yqQ9aND7NJ2M7oBojMxINo/J9cPUobw+OZUTJZEG1qvLnlq
         P8eFlrM8TyTqP13xCnmRKzTWsD5qjB5KxeTP136pP5PRvE+LwQy8TqBQw141qOFmfgdZ
         JzaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=fS1Yrz1eZUQoOwHZmMRDC2gY4H3oYCL5K3j+iaMjoVU=;
        b=TYBgCisk6vo1KPJEMi46+makRc59Kjd6Ta7qKUYJ5KQKI6ts4MRKtWz7lGN/6S8T8n
         mfNLfbNsIOsV+0TQwHpR4FtGP7NYNhOk4KrgjHUAul/s0HfCSksvOTucojSHJzyU+RHI
         HaLLt/OEOTADEe6k9pLsCPa9UO+DtpngraKuoHFLE72Q8j8QZW6/I4PNUfqYW9i9cZIT
         zJGA98/DWY3kpb8eDpacxX3u6Y0dRRcK/DqJDO1gvEhA0NX8XMF9a4scHrvaxAyJYAMn
         J9qsbCuqvK5ZfASW/unb4mG20EnfTW2gkTgmvKOVKuyioWHqFWCdXVxk+CynTMr+YYhf
         Ex3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id t23si1471929lfk.2.2019.08.22.08.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Aug 2019 08:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i0pUE-0000T6-2I; Thu, 22 Aug 2019 18:58:54 +0300
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
To: Nick Hu <nickhu@andestech.com>, alankao@andestech.com,
 paul.walmsley@sifive.com, palmer@sifive.com, aou@eecs.berkeley.edu,
 green.hu@gmail.com, deanbo422@gmail.com, tglx@linutronix.de,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 glider@google.com, dvyukov@google.com, Anup.Patel@wdc.com,
 gregkh@linuxfoundation.org, alexios.zavras@intel.com, atish.patra@wdc.com,
 zong@andestech.com, kasan-dev@googlegroups.com
References: <cover.1565161957.git.nickhu@andestech.com>
 <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <09d5108e-f0ba-13d3-be9e-119f49f6bd85@virtuozzo.com>
Date: Thu, 22 Aug 2019 18:59:02 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

On 8/7/19 10:19 AM, Nick Hu wrote:
> There are some features which need this string operation for compilation,
> like KASAN. So the purpose of this porting is for the features like KASAN
> which cannot be compiled without it.
> 

Compilation error can be fixed by diff bellow (I didn't test it).
If you don't need memmove very early (before kasan_early_init()) than arch-specific not-instrumented memmove()
isn't necessary to have.

---
 mm/kasan/common.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..897f9520bab3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
 	return __memset(addr, c, len);
 }
 
+#ifdef __HAVE_ARCH_MEMMOVE
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
@@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
 
 	return __memmove(dest, src, len);
 }
+#endif
 
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
-- 
2.21.0



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/09d5108e-f0ba-13d3-be9e-119f49f6bd85%40virtuozzo.com.
