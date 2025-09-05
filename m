Return-Path: <kasan-dev+bncBCS37NMQ3YHBBZMH5XCQMGQETUA5INA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id AEE23B46466
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 22:11:18 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3e3f8616125sf635760f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 13:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757103078; cv=pass;
        d=google.com; s=arc-20240605;
        b=bRZu36hktE8m6QCawnAuvEYe7mbMdbaTDj29iyRgMNwtRwkFoNS+c7AUeAeMuH0cMG
         4umXvLMB2XAnnpL3oLLZx1ZUfO2d66uvQ3cFbqq0z4nALELif1VuQRtz/VGvniT0QQsc
         qzfgB8XIsHhLZb0bSR5ckhPzRngdyztwaB5N+j9xTi4/BQPR0vIQMsyzfGrYYlRj+m9e
         HKEM4AjZvV31iJK9B2c341xpNddEdcMKnA+W8gurmYF9nWCgEMqBrh47k776jOPnee4v
         u38gL/xBDjncR7uydu8gNUXhvdANDNyVpGPmVMzSt38c6PP6FbQ1nrvQc3A7OGLp3lpR
         ONIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:from:to:content-language
         :reply-to:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=cJmVknvwB21NSKnQw7L1kUW3falpLFlh/SeEhXYpooM=;
        fh=c9wHH4HAbw8WHU+Efeu29BlZbKKummNn/OjfKI0oAgQ=;
        b=bI3NzcmUbPIB9d/64vn3pX8ysi6juqbTvMiibssFxMUJdF/RySZxsFmwroUJL1bm3e
         hz5v0IkQPpVFz/sFcmPLnmt5uJrDdw5mDGjBzNysmoPutmTXE2ntceD/VeCsHsJZefEH
         F8HORvmoU1YlfGOrZc+N8HVjtWB6lOjxyP5WrTv1yNRrAY2qjF4xl+DdkyMrCYaHwJJd
         Q4c3fxHpY7Rq19+2+SpqJBPOIvuqnhUvhHq13ftlS8UjVIk/57Vyy8+0LNX5qk386e5S
         OO84YJWKwf9p5DKHHFsqfgFEEQyqoG6lO2ImUoiMEUxvEDf8QIGqizU0I+T47ahNEbYh
         WnNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.46 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757103078; x=1757707878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:from:to:content-language:reply-to
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=cJmVknvwB21NSKnQw7L1kUW3falpLFlh/SeEhXYpooM=;
        b=M5FTEuJWrhBeY8kaHkQ4lQS9ZcMwK4JbvXUg5xpJ9z1HM1LEmBxR4rZA2JBUfvmIy/
         K/XCNAmB7WP+7dREsttjMtzjIUBnLMQALNA1ZKp3pVD28ZdhspsdPK95gMsm/JLSCI5z
         /fthqmgUfLJ+1PpC1i94pGqdxRFaY15o95qYFRWMB+wby60sipf2nL/DjzVgVa8WblAS
         rWmtzaJFGU8tNWbjJYsPqD64euLyCnpIpWrDTUjfa4wdkSLZZEouKFSRy1Bw21eXDthf
         Er5Qars7zoc37iqXzXGXvEiwsCU2uSC5iNUU+755smHlsSansyn9gfnVSyKApSCwpakA
         pnxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757103078; x=1757707878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:from:to
         :content-language:reply-to:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cJmVknvwB21NSKnQw7L1kUW3falpLFlh/SeEhXYpooM=;
        b=DgFQsrEY65VoYHH20G1wiYv18IA6XkVVkxseCb462KNtlWhAmUjA7c257y90ibTdm2
         zRAiG2YoB4dsUE/Sf9ivp23EBX+0k6O4cUQ0idbAKeKkS6mIp7SqJjeaeB8xQ1jESlZF
         RKTUsxAlfoZOSuqyGbvll4ibArAu8vPwSrfmpdFwMMK7MQs6foy2iX9zu+8456U/32cx
         aygMwdnZR4aaBBQ7sftIaoZcZx+4MJoCwT9YfEjVJWpAQ94mDpsMDw/v//uTMivz1xwI
         sKZl1K3Nx+jL/1aCjke/f2+t6gynHQIgI+6x+EizGF8e3Z3QfbVSIzCJS1Ha+2AMbFAz
         gSaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmEfN1gc/FWrDESOey6tPDLi0WYap4YLTtIFAbQqJEhLzdpg/PeL2EsB+9KN32HAuGNIJNkw==@lfdr.de
X-Gm-Message-State: AOJu0Yyh5vMM2noXJuHF9i3jIGJd+1e9/CqGpBgRtiVSB8q8Ak/GmxcQ
	3c5YdVNTYd9K1RSFoCqmJJX1xF66n2NjmbEfmy3IsrAMFn3Q5FUxV9Qf
X-Google-Smtp-Source: AGHT+IFEySC6BG8nHI7UC5N7oeV702i43+qeAdnmuqH8jMsYeBoZ5Ctm/iAghsxaJDIxe5cbEDGSPA==
X-Received: by 2002:a5d:584d:0:b0:3d2:633f:d02e with SMTP id ffacd0b85a97d-3e2ffd7fc1fmr3696374f8f.2.1757103077752;
        Fri, 05 Sep 2025 13:11:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfyIJyF7K1vEdio8AyP+wsWbJJr1gn/kR59262QfqKGFg==
Received: by 2002:a05:600c:5026:b0:45b:65ea:6eab with SMTP id
 5b1f17b1804b1-45dd83ee6dfls3290765e9.2.-pod-prod-00-eu; Fri, 05 Sep 2025
 13:11:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUE3sQOOKkMjDbVSmV7RqHJZMeJjTgH+N3nPqne4grbA/3BI43Y2U82/OYScTzStQwyazmeXsme2S4=@googlegroups.com
X-Received: by 2002:a05:600c:1d01:b0:45d:d86b:b386 with SMTP id 5b1f17b1804b1-45dd86bb7bcmr30387105e9.14.1757103075151;
        Fri, 05 Sep 2025 13:11:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757103075; cv=none;
        d=google.com; s=arc-20240605;
        b=A62RuKiS6SsbxB31jTY7n3Y9piPBSkgxE3MhqI81A6QqQeSddQ05TYQ6SFdfzdKpiG
         1WFxvZF5M5pEeVy1XVmRTxrKuGVJxRL5oCidkCv7PbIeSvrUgah0TqIMysvfVcwj0VSr
         7TrjcTRLuw9mn49y06VOWRbd4bTBuhEx56js54aRiA+TN6BaESEI4Q+PPEB5/fhQC+8Z
         YIZcF9QpkHCovjUoLk6tIZ5wBEkVul2CfjI7sLLMjAhwx5ur3VyRb4dnWpiwAb2+Xf2O
         1iYXMyeO0Ud3GUtrZiaStTYHcJc/2J0kyP3qLPEyBOyv+CO1exmmvHU1NPN89paOVJNj
         mJtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:from:to:content-language:reply-to
         :user-agent:mime-version:date:message-id;
        bh=3CNeVBChpPSW3Zw9eLsrTWLPrHpK+4pxoexsckxOXIg=;
        fh=REKRiNPrNm1tBzf7ERwC0QFiIiAVKWae/5jjvKQTGQ4=;
        b=cDmJNh2vOH4y9vL6SdPJ/KC4MF0I/EZIBLU2XljiNopKniGCeS/+RkjXN2MjlvxE5A
         VMyg7OQzmQDf6WWgS2yZt+bQN1M/914Q344wBoVBLNbVtKoeW7wUKpOph7QLFtYGHJW9
         8oRVPtNgKqxSHgLHd17L42UHegiTvzVkPuVK6WypmYSuZrBelOn91JxCTDSoagyhXzzk
         JGcKKJfJWhEcbu1krWaA9kcanWlb14BqAZ2IgCUXkI1L+iNDKLejuscR7ONqjunNFhvs
         Q7E0yRWq+4H7VvXvz+hXb6ZkgRU0A5MC+aKcFUcJ/4cOXYmIbFqzVCGwgiE6lY3Ot+ra
         F7Dg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.46 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=linux.com
Received: from mail-ej1-f46.google.com (mail-ej1-f46.google.com. [209.85.218.46])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd5fb250bsi484935e9.0.2025.09.05.13.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 13:11:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.46 as permitted sender) client-ip=209.85.218.46;
Received: by mail-ej1-f46.google.com with SMTP id a640c23a62f3a-b046f6fb230so426078666b.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 13:11:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWniifFUMmaCG5MtcdBfpTxvf1NoHEmYbiCfCPONFY8xcXN7pJmcVzorcOEXuBvVKxF2DntDJqNSig=@googlegroups.com
X-Gm-Gg: ASbGncsUpFBCWtjz3iEci2XgddAdAFGukBEUxD9FHOzD9d+eE4ChYaYZkuv3677zTQb
	wscGewJtXt8U0Mwp3HcB0XOWb/DbFzoV4DDim8RdH6Zm+7gRRL6O6yI+TKPxuC8/nk7WMdkXGJA
	VXzh6fLTkdcDQqu1LAVaIYWDMHETBlgTjh8Zxk0rtuGvzOoMZ0KUea1g3HQNJ6RtaMfcKa1EU0k
	H7DpiJuKxRXuuf6aKP3+McQayzaAcSOyaGlA7FM7/WKD0aogJY9QAI31YV2fPaVnuSOxuTPWyn+
	ISabM4H5FnWtwyn1jEzGNiWQD77OOHRZAUmZ4F8ia/7VMWA48uwwGZHcSLkkYCBRubLbQq1YHqb
	IC7Dn2vy2nssc2Maagfw=
X-Received: by 2002:a17:906:dc93:b0:b02:d867:b837 with SMTP id a640c23a62f3a-b0493084d31mr511388866b.7.1757103074299;
        Fri, 05 Sep 2025 13:11:14 -0700 (PDT)
Received: from [0.0.0.0] ([89.207.129.98])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-b04190700a4sm1471790666b.63.2025.09.05.13.11.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 13:11:13 -0700 (PDT)
Message-ID: <01d9ec74-27bb-4e41-9676-12ce028c503f@linux.com>
Date: Fri, 5 Sep 2025 23:11:10 +0300
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Reply-To: alex.popov@linux.com
Content-Language: en-US
To: "kernel-hardening@lists.openwall.com"
 <kernel-hardening@lists.openwall.com>, linux-hardening@vger.kernel.org,
 kasan-dev <kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>,
 Kees Cook <kees@kernel.org>, Jann Horn <jannh@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Matteo Rizzo <matteorizzo@google.com>, Florent Revest <revest@google.com>,
 GONG Ruiqi <gongruiqi1@huawei.com>, Harry Yoo <harry.yoo@oracle.com>,
 Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>
From: Alexander Popov <alex.popov@linux.com>
Subject: Slab allocator hardening and cross-cache attacks
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.46 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=linux.com
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

Hello!

I published the article "Kernel-hack-drill and a new approach to exploiting 
CVE-2024-50264 in the Linux kernel":
https://a13xp0p0v.github.io/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html

It's about exploiting CVE-2024-50264, a race condition in AF_VSOCK sockets that 
happens between the connect() system call and a POSIX signal, resulting in a 
use-after-free (UAF).

I chose Ubuntu Server 24.04 with OEM/HWE kernel as the target for my 
experiments. This kernel ships with kconfig options that neutralize naive heap 
spraying for UAF exploitation:
  - CONFIG_SLAB_BUCKETS=y, which creates a set of separate slab caches for 
allocations with user-controlled data;
  - CONFIG_RANDOM_KMALLOC_CACHES=y, which creates multiple copies of slab caches 
for normal kmalloc allocation and makes kmalloc randomly pick one based on code 
address.

I used my pet project kernel-hack-drill to learn how cross-cache attacks behave 
on the kernel with slab allocator hardening turned on. Kernel-hack-drill is an 
open-source project (published under GPL-3.0) that provides a testing 
environment for learning and experimenting with Linux kernel vulnerabilities, 
exploit primitives, and kernel hardening features:
https://github.com/a13xp0p0v/kernel-hack-drill

In kernel-hack-drill, I developed several prototypes that implement cross-cache 
and cross-allocator attacks. The article thoroughly describes the procedure I 
used to debug them.

After experimenting with kernel-hack-drill on Ubuntu Server 24.04, I found that 
CONFIG_RANDOM_KMALLOC_CACHES and CONFIG_SLAB_BUCKETS block naive UAF 
exploitation, yet they also make my cross-cache attacks completely stable. It 
looks like these allocator features give an attacker better control over the 
slab with vulnerable objects and reduce the noise from other objects. Would you 
agree?

It seems that, without a mitigation such as SLAB_VIRTUAL, the Linux kernel 
remains wide-open to cross-cache attacks.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/01d9ec74-27bb-4e41-9676-12ce028c503f%40linux.com.
