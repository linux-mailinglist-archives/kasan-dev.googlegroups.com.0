Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB4PE77XAKGQEIM67NWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC1C910CC8B
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 17:14:42 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d24sf1281931pll.14
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 08:14:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574957681; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjQF8asJoEiGhSbixxQ11Z40w9gC2guakkN1Spd8Pi2fRtOTSXtuWHEWwatiIZdG44
         wn8RlYxnpuGGgFSL7UbhEJaczOHnKKHbsKoScquaj/lsC9pyHUv9j23hyQzEuXlUXw3z
         3s2S+lv/VcstCrtT4oR0oRNTLuuPQ9JgCtM1S6VpAGGjo0xxjuVTfQ4cAXKy9BWXoHF6
         4PC6oiydS+hQlwGtoeLV+Fv+1N+MdkUPgw7+hPg2RhuqqBYpDGo/VWbXh7kYlb9TBqms
         cXzavntmBxWLbxx6Jc6HQnPbwSygk+r4U+keYzPVAcM3wTnwxj0SVfpFn5XCaBIqwFnh
         ZtSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=Yhye+ie11oi07RsyFPP+DPg4H8+0NRPXy3PJFqqlgAo=;
        b=xt9dlP4464RlbCP6aSJKHAQQIAaQqih547Rj8eE1n3k2z5avYFx1HtfR2QKL+q9fcK
         jfym9ceJxfcAYPQebhdi4FPNsBSLyDxfri/WnN3yrFSI7fP0lcjnRZeWoKnUvhxEPUmk
         nLzAYBXzK6XPC0z/hokhmRCnfeCn8vRPUCFfTbjZWxyWt+fuuU/0JnRQxK2CJriOKTjR
         0cBHTlmEpjEXslJIlZ/Pe34Mae0aUbe0d+0nCzpqFSMsekz9EMs5imr2CPaf7ahjS9ae
         ugjO5hq9fsFjka8TBH3Vikiv4nZSicMGwtT/2bX9EqtIEIt5rZB73TqHEqcjMBOf+AxD
         iHHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=GE+oxFtg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yhye+ie11oi07RsyFPP+DPg4H8+0NRPXy3PJFqqlgAo=;
        b=FhKQWPfeZdgtzEQN4HF3xIHwosaC3sIWePxQmFQdfC6u5zKK7ZtaipGFPmJmht6ZLk
         IajMZPphmQsMJlLm1bNi17K0PmBAcQpKuulzpwrs4ddVnxFqHGBgFm+c861k1piUnnoC
         V3cVU71M2UdJzo9236S06zm3Lrz5Y7tRUztFDqo391Vl3kk9ZPPqcrzfTyQcJbjeZKhH
         nHvEyVXLscEaDna3HWw1NWIlrabgqqpNKepj1UAjtpdPI0svNpzz6Lo3jjygORlOrm5L
         ZfmkBUQp66LUdvq/+QX+vjiiHlPioK4yIYdJgjPApCS8y6NPH/1nfIlbAoKfGwRB5JOy
         tVqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yhye+ie11oi07RsyFPP+DPg4H8+0NRPXy3PJFqqlgAo=;
        b=AvoVcDOnLYKN5QFSKSU5UTJaFFk0W6f7SynmrhH76YM/+ys9KdLnBAWARa8Tfy1St+
         QoQgCpfDQ8OuZQgH4Nv/uJmK9TlL682881JZ7h7+YC5e2LeQeyPQJUCWb6apf6yUYxTC
         f3D3oH9TUQcmr9DF0kePV7SphEffyIR0ZV0jUSGlCVPVAuJg4TMAoMx/F3UQzmuJdImO
         MLyTBQf8oSXds5ZR1i+cNJ/QA+y7W2NZ9ZLbgVbpqjNj6xBGogY20VsLK//CypyiIu5g
         KAaZBstTG8kcKLYlMgGRNGyAhaKFSAS9TN/0CXFp8OLCX5Nvcd6nFq808aFxDJpL1dsE
         pDwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNypZiWWMdk4gp0H9RB9exiybiNMiGCll88EX5A1XdExEhVSVL
	MnEmGAnuS5USIkKmrvEAQNo=
X-Google-Smtp-Source: APXvYqxIyY474uIyOjF2OB+Wo2E8eyopBibAN4GHJtp1Nbd1koDZba8HqQe+UrG9dh+UZSVdkbiSrw==
X-Received: by 2002:a17:90a:8083:: with SMTP id c3mr13632013pjn.92.1574957681218;
        Thu, 28 Nov 2019 08:14:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4b03:: with SMTP id y3ls6535678pga.9.gmail; Thu, 28 Nov
 2019 08:14:40 -0800 (PST)
X-Received: by 2002:aa7:9ab0:: with SMTP id x16mr52673898pfi.139.1574957680860;
        Thu, 28 Nov 2019 08:14:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574957680; cv=none;
        d=google.com; s=arc-20160816;
        b=lGutwvOiHpoUmEZL3NxFDGRQWJEo9KeOdOXBHBiyeK3JRHbcsXFiI/Bmwdq44xSpZ4
         4adDTFtCgybb38yCHSqHuryWjwsIy/4DTjVhzwQVMMbUKv6XD9d/vYjCObqEeuw0CQzn
         APT0wQXsQlPKtwl6XPitzYADDoUO/iVQgjdmsvnIBgAQ/efvEARqfKDxEvXzVQ99fPUx
         P0y/gC3oFBdaxgWhhQh0/Y1A4g4qeHylnIoIvr3x+Skx3WHg9KszQvR/DGe4uqTndruE
         +F8r+U2kaPhq+4QSrKrvFfCHXysgtKDEN5/1HeDYHq5mkNZyyX4wAdhPn7/D3qWC/yMe
         DQow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=swAWjg0mWyZStjQq/JoheoQkEGMMdPmGAhVcEaoY9Xg=;
        b=uZ4VzQR8jgWdNMIeKGT4OiQYw+TCRpM9QK5xDfWhd8GgY6/J5z0mZqyhvcY4LSvNBW
         oipSzZ72mP1kNXmjEqTXco38u1T/GFx1RzewOHMjyMPVJbmXlEK9SDuwW2f2+dzB0Xj6
         r2hwCzkRYIkZjXW6vhJbvRpG4OUUp6WMa0XZXbnN49bu/BjZW91K0cPI9ANXxa/F2t88
         7jy5/vUR9fJP8D6BpLBf84j5fZ1yJIQg6eS++u/DZCK3uxee7RsmP4fubLID9DTRrhi1
         ltIu0s7oOCDxA9Wak4wGRxvQRS6bZ4awJ50snS/zl5hxETUWpnnGhg62N15PMzLHuEHk
         76Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=GE+oxFtg;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id m11si355867pjb.0.2019.11.28.08.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Nov 2019 08:14:40 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id v23so15348436qkg.2
        for <kasan-dev@googlegroups.com>; Thu, 28 Nov 2019 08:14:40 -0800 (PST)
X-Received: by 2002:a05:620a:13cf:: with SMTP id g15mr10594494qkl.195.1574957679840;
        Thu, 28 Nov 2019 08:14:39 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id x8sm9260293qts.82.2019.11.28.08.14.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Nov 2019 08:14:39 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
Date: Thu, 28 Nov 2019 11:14:38 -0500
Message-Id: <4B3C1889-DE01-43A5-B0BD-0CFC33A5315A@lca.pw>
References: <CACT4Y+a-0ZqGj0hQhOW=aUcjeQpf_487ASnnzdm_M2N7+z17Lg@mail.gmail.com>
Cc: Kees Cook <keescook@chromium.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Elena Petrova <lenaptr@google.com>,
 Alexander Potapenko <glider@google.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 "Gustavo A. R. Silva" <gustavo@embeddedor.com>,
 Arnd Bergmann <arnd@arndb.de>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com,
 syzkaller <syzkaller@googlegroups.com>
In-Reply-To: <CACT4Y+a-0ZqGj0hQhOW=aUcjeQpf_487ASnnzdm_M2N7+z17Lg@mail.gmail.com>
To: Dmitry Vyukov <dvyukov@google.com>
X-Mailer: iPhone Mail (17A878)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=GE+oxFtg;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Nov 28, 2019, at 5:39 AM, 'Dmitry Vyukov' via kasan-dev <kasan-dev@googlegroups.com> wrote:
> 
> But also LOCKDEP, KMEMLEAK, ODEBUG, FAULT_INJECTS, etc, all untested
> too. Nobody knows what they produce, and if they even still detect
> bugs, report false positives, etc.
> But that's the kernel testing story...

Yes, those work except PROVE_LOCKING where there are existing potential deadlocks are almost impossible to fix them properly now. I have been running those for linux-next daily with all those debugging on where you can borrow the configs etc.

https://github.com/cailca/linux-mm

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4B3C1889-DE01-43A5-B0BD-0CFC33A5315A%40lca.pw.
