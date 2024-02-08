Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBSEFSOXAMGQEROOBKLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7374D84E03B
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 13:02:18 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2d0a20a788dsf18047921fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 04:02:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707393738; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ot+GccOqQBnaA2ldTKQ28WpkdqYgl9TJrmVZesrcE1sRhD/LXpsNGFRqqXk3WTHz3R
         8CoUJ9Y+AHGQj8D04aOhraCEQQ1uWmVbm2i2e8q5rkcCGXKITxfSao5B5VVdkVfflPGh
         mEeGiNuRYKf7OVcCXEvzxuQvxPH8CDw0TWmIcexTDZOw/LyCQJRjDf39yYJR6pK8oGoN
         VHcKeeRiqcayj4l8BR4F/FI5/Ss+WbvZvfF/i3RrBbgQYXvu9IJQifQZtPs7w2w86H3C
         bqrJtYep8kdJ56yVz6wo/GAMTgnTDYMsO/XEq08zNOadJEdwr9N7Q5TTMXPH+Pr9yqoA
         G3OA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pAtpfKUhyf136KY0U6+PF2ttZAdtzKH1vtXf2xqAn5g=;
        fh=kqVTNELnxy0p//NDIXAHhIn+wbNLqkuy3P4B4SHxEBk=;
        b=Zsz1eU6lLz+BfaIFZ5cm9iislobZgoF2/RdMKXrQud9SvZ7BGAWKoU7EX+duDAPogj
         Xcpm01fYFctW39keAAhxBIOiRd8dM98bzTLKwMzjXIlp0qPUhc/tWZRA1oGhFFDzxiOv
         yK0v6eyrZf+N+TGTpKxqDR95YVnkC2LXE+jS9Ev0icz1qqAHEVJsCtO3SmfEf8t0vzeF
         YD1d5hdnHBcRjlxYRBtiJox4LxgxhUugQnq9B3h+GxW+nHL7szUyUDoFS1doi3Jdowys
         XQNNeC4PUDIzbZuwwa6fhmK111UOKe5u1dza1ASMCtVTP0YRBTqz9AOWaeomPl+wAluW
         8MOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=lM1FqGOB;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707393738; x=1707998538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pAtpfKUhyf136KY0U6+PF2ttZAdtzKH1vtXf2xqAn5g=;
        b=Sffl9kh5esKDqSS8wTiFz8aleENIP6vhKZJHsRn2fqNklV4RHlfjXTi4UAqa2CWO1R
         2b1vJjSWMECksLvX5QHKApT5eZVRjQW5Ti4HHmVOTVwI+ZYPMzS4S6L/ZDVzKRZi5hqe
         eirSnj7TJnZR2eE+aGc5R/2BSGjYj5VkblnYRMtaTbCf2PAeSJWyh4m9Dkq1Sxi1dK0M
         +V3IEKhCiw48iXYHtDrOyIChh5F+FG6OBDJD13VXTGNQhZwxRclvhz0kj9gfM3mqpgFQ
         9UllzUEZwtHT2KkB09+ZTD23yaOE/gd7p4rEVyt4mofNHamJuSfldSbGhe7k7o5oxhGv
         ZY+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707393738; x=1707998538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pAtpfKUhyf136KY0U6+PF2ttZAdtzKH1vtXf2xqAn5g=;
        b=PMEX01lEnWYmXFNE0lKhgm4NTFeuay+Rl1iKL2HM7EX/FlyZoqAx5gEAy5voeBFBU2
         nOzc6cIEWa11wGzjKYXXD3AVcuziq93U4qDanduOAUPi3CJNIKwJQ8X21V8SNAXxMcQ9
         KWoooh0iAD4uTi/rTwVyIsmfJz1+ENVJ380JFjBwdVlL9CSBMFsJGdi396BiQbc3R0lI
         Mj6W97MYl7AzR+c6UmMeLthQr/kst+JcRKtVNMPNG6SFhfgQf5BEymAiD9zEXk48pXcv
         5ipzDGTlXWSyzSk1aV9w5obazOo74vY4QAkcGG5GoKF1bQErdIkoN4MSzLN6uBvrLnUU
         J3FA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwOZrOhRp3RDxtu7pKgSXHeAAFI3NMeU8cGTDOaVbMFi3TlbuUL
	0WhNeQ++S2SGWJhZsu5NEtt3PRnW4CDEQsWJF5zt9sqJlUfN0Nby
X-Google-Smtp-Source: AGHT+IFQjuBjk6dsnlT8da8iFvho+vEeaPyTiO45E77zghSGUN5rKHGXZmHEFYQTIJ39B1dc9GsMKQ==
X-Received: by 2002:a05:651c:2224:b0:2d0:c95a:f3c2 with SMTP id y36-20020a05651c222400b002d0c95af3c2mr4195317ljq.10.1707393737073;
        Thu, 08 Feb 2024 04:02:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3304:0:b0:2d0:9108:f90f with SMTP id d4-20020a2e3304000000b002d09108f90fls393283ljc.0.-pod-prod-01-eu;
 Thu, 08 Feb 2024 04:02:15 -0800 (PST)
X-Received: by 2002:a19:5f57:0:b0:511:51a9:7759 with SMTP id a23-20020a195f57000000b0051151a97759mr6711121lfj.64.1707393734958;
        Thu, 08 Feb 2024 04:02:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707393734; cv=none;
        d=google.com; s=arc-20160816;
        b=BS3uvLUZIJHiBq1YyV20oh+HG/rb4QYe6nfYt5u3d6ol5EEkLUqxEvyvoZQKWB4ekI
         ybD6WuR58gqXIdr3WO9iYwMcyO2pTkUmC52VBdtPUwK9F0Q5CT7LKttlC4Y4LeSjG+/P
         pzr+ErUBX0VBw/J7OqkEfbY3XUWYUcuxSRq4w5ZOHuaKdAIO6+9i1XH+/QvbpIaC5H38
         C4o20b5ra684GbEFuzJ2p3SveAMaISKGorbXHCcVMHjzrQDSJ5xar/dF0e4geIaQxblR
         kCOI+FLsk4ZCYlAHZt2WEuEPn+Kokulq9ir9Dtcb3XTORDu/kDBrtyGX9InV0gdIbR2k
         Z+7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zk/yQO1YQSF8AvGqaFxyrvZfxFZdDX0y82nrj5ssPQA=;
        fh=kqVTNELnxy0p//NDIXAHhIn+wbNLqkuy3P4B4SHxEBk=;
        b=g81QiprXyxItJD2vPOU5bZ35lczi2n5lbvwA0a3zy0bhlnxEph83MQyHiXN39kcHQp
         jMCIwmrX+scfBY+VuY2MFqL5QN/LNiB/v5VNtfziYQL7ZVTkUZ3EfVtgPtDwUxU+ypdD
         +LFIg8DO72FHBx3kOWkUFGVwlZfxmOr2lqm8dxy3d2H4DhF5vT1q8xR92GWnJpYg1Tgk
         1PyjsJ8dN81YkZKgo8qITi7lWBCn4axpcU4FaVxkU4pFzyPWsIEBuS/IfJQGnlBRlTfn
         YyIhXK2l4/2CJqa17VfsxWuEIackhBaPLmaBd0Y8917PgF2ILEu8nLFH1RQgniOpL88u
         STQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=lM1FqGOB;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
X-Forwarded-Encrypted: i=1; AJvYcCU46aRdB1m8Yl5BKzQNws+vnysn3o3NRe+vZstzWodYlTIdjIQ49n8f4utz8tOC9ErCNMQ9cuouL9HthugF7RwSsoNQYIlCOj6wEQ==
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id o14-20020ac24bce000000b005116848964esi236594lfq.10.2024.02.08.04.02.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Feb 2024 04:02:14 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id C38B640E0196;
	Thu,  8 Feb 2024 12:02:13 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id lV1XahIN3clY; Thu,  8 Feb 2024 12:02:12 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id BA2DE40E00B2;
	Thu,  8 Feb 2024 12:01:59 +0000 (UTC)
Date: Thu, 8 Feb 2024 13:01:55 +0100
From: Borislav Petkov <bp@alien8.de>
To: Marco Elver <elver@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>, Matthieu Baerts <matttbe@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Netdev <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org,
	Kees Cook <keescook@chromium.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: KFENCE: included in x86 defconfig?
Message-ID: <20240208120155.GBZcTCs-Jkqtrg42Zd@fat_crate.local>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
 <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
 <20240207153327.22b5c848@kernel.org>
 <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com>
 <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
 <CANpmjNPgiRmo1qCz-DczSnC-YaTzpax-xCqbQPUvuSd7G4-GpA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPgiRmo1qCz-DczSnC-YaTzpax-xCqbQPUvuSd7G4-GpA@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=lM1FqGOB;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Thu, Feb 08, 2024 at 12:12:19PM +0100, Marco Elver wrote:
> git log --grep 'BUG: KFENCE: '
> 
> There are more I'm aware of - also plenty I know of in downstream
> kernels (https://arxiv.org/pdf/2311.09394.pdf - Section 5.7).

Good.

> This is a problem shared by all other diagnostic and error reports the
> kernel produces.

Yes, and it becomes a problem if you expose it to the wider audience.

And yes, nothing new here - it is the same ol' question of getting good
bug reports.

> It's not a KASAN replacement, since it's sampling based.

I meant this: "Compared to KASAN, KFENCE trades performance for
precision."

And yeah, I did read what you pasted.

> From the Documentation: "KFENCE is designed to be enabled in
> production kernels, and has near zero performance overhead. Compared
> to KASAN, KFENCE trades performance for precision. The main motivation
> behind KFENCE's design, is that with enough total uptime KFENCE will
> detect bugs in code paths not typically exercised by non-production
> test workloads.

What is that double negation supposed to mean?

That it'll detect bugs in code paths that are typically exercised by
production test workloads?

> One way to quickly achieve a large enough total uptime is
> when the tool is deployed across a large fleet of machines."

In any case, I'll enable it on my test machines and see what happens.

> No reports are good. Doesn't mean absence of bugs though. :-)

As long as I don't know about them, I'm good. :-P

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240208120155.GBZcTCs-Jkqtrg42Zd%40fat_crate.local.
