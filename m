Return-Path: <kasan-dev+bncBCT6537ZTEKRBA435OOAMGQEXCZYLZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 65ED664D745
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 08:32:21 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id b16-20020a17090a10d000b00221653b4526sf1080438pje.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Dec 2022 23:32:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671089539; cv=pass;
        d=google.com; s=arc-20160816;
        b=QQTflX4YrggKc7Gf0T8bMTRhpvEH6FSMWPSHUmbJopKhpSxXZVWmYCKRcWPcuQm/i4
         Sk0STo72ZgJuPgEzuaiodEY7RWtM3W9neVmRYGxhs5Yvz1cX0MAml8/pVXKkcc2LMJB3
         xM4mDdaNBG0y5xQQkyf132DCtUze2ermF/ONR5Mn42YdagBuMppCzWPIanBQltmYB4KQ
         o7175SNxIqBEVDZfWp2z7RjDRbxbehoYsklYHTlsVfInfAOEhhEOyAHPZ1kENBIijzdD
         JjO+EnaCQPwxoryBrDE4LY+ecd0+jUNhxaO9I/XYCMvjm83qIwHcBkrpf9Wb5UKC7jQ/
         JNcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=fUQduJCRPMkcqNYeddqJmrfm11vOJq1zgMbKQ3SIof8=;
        b=Lnqt4dsOcybcYN35tzGhtcqdwxtS48Ir544sFjulH5cSmz+dheW1WBRkmnB9PxZh8t
         XXK4lwe5BRlGhKNf5gdBarTqSZ52ZcccD8CW8WzugsWfbomWRZ8Q5QRmFB5C+DUqz0W6
         CoavvgIc9AnFfeT3dm4QY0nfq2FuCLiFMa6lV6FTpLdDRbvfvBlH4mhOSigzU/jAwYJg
         AOXSNCSIqTgLYoPM3d3/Xqo1o2mWuHVu21e/kr3o2zxAmLqoShp7v40N1LRTuBb4UOZa
         DKzo8TwBbzdmc3YWVcWeI4YCLLgAhBgQ8CG1M+nKih9kgHED6GB1FTLkWYd55VfsWF56
         gg7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vqHWFXqE;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fUQduJCRPMkcqNYeddqJmrfm11vOJq1zgMbKQ3SIof8=;
        b=aVxj/hmYt3kayf+V9s1yAHf2XUe/vY5KGPmOG94is6INh+Ycrv5ZWgqhiLIWhhuFDl
         i7IJpOuJEWwQ7uepTxRvFiksdhfu7WS9pTl2A+nItBMltbZVaOVB58D+dnHlkREXf75e
         TPCOyCYJoTnyH08I7K/b0dFnqQinGERa1juQQl2VsE95W7p6lbh8FAZK8ks4S/x3IF1h
         j1AiCRcEEJNlcqHk5rwrMkYqnf9KOHJLaSa2UoNbdCtBHX1t97GghjyvrIB6MjP88cZE
         AIbUatBC7xoSnJWGiAmRPfdPc3ERdM2Odwps+tcsmTlRPMfSQn685cu/C2tUOFkrTujb
         lCMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fUQduJCRPMkcqNYeddqJmrfm11vOJq1zgMbKQ3SIof8=;
        b=cLgtDruei22cDbyRMikUWqVU24/AIsr1preW7TU1YdrUmUq9wc5NJTXFNyQKlvc80b
         XcYG4tbL9R4V/KX3vG8KeiX05+Xnf9gaJAxKwaXXf/8XpDbm/4oJdgPe/XM/xYeax0IV
         HMgrCrM77XNYJYpxL0AlFAJ3YPeo9cSNGhMVXHtahLs8Oa2iZ4aXgkg6acq1rXJAV8cH
         ME1v4294c/MQUwnf/TXRq4UKnje0H9rjpJhaYVJm/VobBcGoJw0DsHOWJ6idY7KjmkoV
         6TCVtUl5sYaJAqFl3KsokUkx4fuJk4uZGDyt+EqPylEVo1AM6nK0dWHvKVi0tU/uxTqp
         RrIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn9sHJXkn004I/wsVBT95NuWGC5XvQqOoHK2dTA1Vr1lmtBUuP1
	H3HLwO+lsDKJwzjn1EqAGFg=
X-Google-Smtp-Source: AA0mqf4RkRrF0HK5QElx5mYiwLYy8s3R1qJ1DfSjXtYGYzyO71NV3N5MRgKWr2tubAAEd9SloHXukQ==
X-Received: by 2002:a17:902:9890:b0:189:9301:9c1d with SMTP id s16-20020a170902989000b0018993019c1dmr47409586plp.28.1671089539459;
        Wed, 14 Dec 2022 23:32:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:898e:b0:219:4318:f24e with SMTP id
 v14-20020a17090a898e00b002194318f24els2101724pjn.0.-pod-control-gmail; Wed,
 14 Dec 2022 23:32:18 -0800 (PST)
X-Received: by 2002:a17:903:515:b0:189:bcf7:1ec0 with SMTP id jn21-20020a170903051500b00189bcf71ec0mr28011353plb.30.1671089538707;
        Wed, 14 Dec 2022 23:32:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671089538; cv=none;
        d=google.com; s=arc-20160816;
        b=SDSDhWS3CdVxxJdfn6jbv7aqD4NujuM/JTLvg5cO6kqAHttcnIFgfJMLkeTrRNtMy5
         bghyBmyspOvidATPTJMIHc0w71ky0JozlhiyzhZg/MVWeillErzjwgwLuK/EWeB6RaqO
         u8ivfZYGNgyTCeRIokhovGnqTsVYgem5C/kHeNdrE7desGSUslVOhcqrdpZwjQUNbJl1
         IOfDMlQXDtwPK9YyhLN4/J/lXrsLI5RzQnLwzzC5q/P+8+V4XI3lzH/6tMSssQjQ9Uzp
         EmF0rkbvj64HFb1mNJzeskP6YtT5xTQsz+uUwHrVN0cWqhNZn+vVocPRpYWOgMxIfwqH
         iqLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=oNTsmDDapjb0QCUT4JkH1Ng5FzflwQuaskNm+11VdTk=;
        b=vIjvvPXzYmyOMjLh6DZS3CzHcvIy4TM2N8JB7+VyjrvgN3Gnzf0k9gbrWzDkbpNbCr
         4mtT41MWLhoBvaFQRsDn9czCgD9G7kseOzJ/tmzalJWyPB/Bc1j70tStJKOnJ1WC4EPs
         ga4wm3/l+bJmgWKlo28OL5eWILOq+pBk/A7zvUdDaPMZD3auCt/WbabaEFOdMcpYjuf4
         ld07LfRvtPRcqAmMGR4B5kPiSrtcC7SN7HXBxt/Xx62ltHcChT870x5BoSzxmXVn20lB
         M0nM+EIyPY8p4Y8j16yqmpdgT8BO0Hi4oWUvv2tmBuesZdXk1mUYzCPkJyP1aon/OIAy
         asfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=vqHWFXqE;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id c9-20020a170902d48900b00188a88cc62fsi574407plg.12.2022.12.14.23.32.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Dec 2022 23:32:18 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id s25so528330uac.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Dec 2022 23:32:18 -0800 (PST)
X-Received: by 2002:ab0:6201:0:b0:419:da15:be26 with SMTP id
 m1-20020ab06201000000b00419da15be26mr8686832uao.115.1671089537713; Wed, 14
 Dec 2022 23:32:17 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Thu, 15 Dec 2022 13:02:06 +0530
Message-ID: <CA+G9fYvcmmOh93nOti72+woKvE+XvLg7apCYDUfu6oKtjPkHKw@mail.gmail.com>
Subject: BUG: KCSAN: data-race in do_page_fault / spectre_v4_enable_task_mitigation
To: open list <linux-kernel@vger.kernel.org>, rcu <rcu@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dominique Martinet <asmadeus@codewreck.org>, 
	Netdev <netdev@vger.kernel.org>, Marco Elver <elver@google.com>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=vqHWFXqE;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

[Please ignore if it is already reported, and not an expert of KCSAN]

On Linux next-20221215 tag arm64 allmodconfig boot failed due to following
data-race reported by KCSAN.

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

[    0.000000][    T0] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
[    0.000000][    T0] Linux version 6.1.0-next-20221214
(tuxmake@tuxmake) (aarch64-linux-gnu-gcc (Debian 12.2.0-9) 12.2.0, GNU
ld (GNU Binutils for Debian) 2.39) #2 SMP PREEMPT_DYNAMIC @1671022464
[    0.000000][    T0] random: crng init done
[    0.000000][    T0] Machine model: linux,dummy-virt
...
[ 1067.461794][  T132] BUG: KCSAN: data-race in do_page_fault /
spectre_v4_enable_task_mitigation
[ 1067.467529][  T132]
[ 1067.469146][  T132] write to 0xffff80000f00bfb8 of 8 bytes by task
93 on cpu 0:
[ 1067.473790][  T132]  spectre_v4_enable_task_mitigation+0x2f8/0x340
[ 1067.477964][  T132]  __switch_to+0xc4/0x200
[ 1067.480877][  T132]  __schedule+0x5ec/0x6c0
[ 1067.483764][  T132]  schedule+0x6c/0x100
[ 1067.486526][  T132]  worker_thread+0x7d8/0x8c0
[ 1067.489581][  T132]  kthread+0x1b8/0x200
[ 1067.492483][  T132]  ret_from_fork+0x10/0x20
[ 1067.495450][  T132]
[ 1067.497034][  T132] read to 0xffff80000f00bfb8 of 8 bytes by task
132 on cpu 0:
[ 1067.501684][  T132]  do_page_fault+0x568/0xa40
[ 1067.504938][  T132]  do_mem_abort+0x7c/0x180
[ 1067.508051][  T132]  el0_da+0x64/0x100
[ 1067.510712][  T132]  el0t_64_sync_handler+0x90/0x180
[ 1067.514191][  T132]  el0t_64_sync+0x1a4/0x1a8
[ 1067.517200][  T132]
[ 1067.518758][  T132] 1 lock held by (udevadm)/132:
[ 1067.521883][  T132]  #0: ffff00000b802c28
(&mm->mmap_lock){++++}-{3:3}, at: do_page_fault+0x480/0xa40
[ 1067.528399][  T132] irq event stamp: 1461
[ 1067.531041][  T132] hardirqs last  enabled at (1460):
[<ffff80000af83e40>] preempt_schedule_irq+0x40/0x100
[ 1067.537176][  T132] hardirqs last disabled at (1461):
[<ffff80000af82c84>] __schedule+0x84/0x6c0
[ 1067.542788][  T132] softirqs last  enabled at (1423):
[<ffff800008020688>] fpsimd_restore_current_state+0x148/0x1c0
[ 1067.549480][  T132] softirqs last disabled at (1421):
[<ffff8000080205fc>] fpsimd_restore_current_state+0xbc/0x1c0
[ 1067.556127][  T132]
[ 1067.557687][  T132] value changed: 0x0000000060000000 -> 0x0000000060001000
[ 1067.562039][  T132]
[ 1067.563631][  T132] Reported by Kernel Concurrency Sanitizer on:
[ 1067.567480][  T132] CPU: 0 PID: 132 Comm: (udevadm) Tainted: G
          T  6.1.0-next-20221214 #2
4185b46758ba972fed408118afddb8c426bff43a
[ 1067.575669][  T132] Hardware name: linux,dummy-virt (DT)


metadata:
  repo: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/tree/?h=next-20221214
  config: allmodconfig
  arch: arm64
  Build details:
https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20221214/

--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvcmmOh93nOti72%2BwoKvE%2BXvLg7apCYDUfu6oKtjPkHKw%40mail.gmail.com.
