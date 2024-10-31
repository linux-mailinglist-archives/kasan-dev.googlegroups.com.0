Return-Path: <kasan-dev+bncBCKLNNXAXYFBBY7PRS4QMGQEVGORLIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9543B9B75CB
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 08:55:17 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-37d67fe93c6sf366566f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730361317; cv=pass;
        d=google.com; s=arc-20240605;
        b=fIboakcFcIhvAVXHEh+LAg6/vNmRN1dSFrVX7KSd9YPRCu1aMIVbtABavCfY0/RZz6
         enIiRGGPSaSEpmml1gRBzZluhMtLMnA13Pv7I5V5JbV4RwbnB+NFOgeaDO6sySdTu3ON
         YGdwFJIw2rOwe/EoxRs3i38DPDGlk2n2NjpgbRpZ1wNQyKmIsf6J56C9Z/YSHdCCnXUP
         dpPdhpglM4AUObP6+QPYHZ/I4XtOuyQuxfTmeLanth9jGI81PstZiFI2LKHi75jMpDQ+
         spPhnqIR299mpEui3NkvjfFGmifLBeAmw74ClbRGuasj1/5uCtgaD0YyMyOFmo480/Ss
         kWaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7igFyRz1Em4vqLMk1CGIR4FjEz17i0UegyNILfzCJjk=;
        fh=gmQc4fXntlWXBY3nDlj/2IQpM24ZmAX4OrL/RPTGo1E=;
        b=ULu4WVVSrSthy0t1RjI028k4q/693AekLgNcFEZ2XLQoTR8PNHHhiZxNJDtO8CNqfq
         ID3QI5MTJIaZ9VRAq3wO5rnlZBQX0hm62db/KQ3rKCTSyO+7LYgip7npGAFEFEwFmq/T
         QdQ2X2rkyBAIhW2BDmKvsC29BemyH2DE/zl/f4e6Ih/Nr0/b3Dg6VZjWjORRICZX+fg2
         kNekqqPA3dBpYz3YLBpsOlbAmOW971pLudw7i3ABz6iternxlFNLRbErbwPmc9QnqVmL
         GBJ3/10fa/IJ5/3Uo535cwX1ZiyJWFdDrTxeFmrnqWeijsJ44k1fNJiSB27QFq7kjjFR
         Sfdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=r57rkDgx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730361317; x=1730966117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7igFyRz1Em4vqLMk1CGIR4FjEz17i0UegyNILfzCJjk=;
        b=wiB91VzqLB7wXCIuFEcCkUoZXoOVW0OzECqvJ6Qgqr5W+dNOa47yTNrKL50QAJpQR6
         kM33CjtakQfYACIG3R0N88BbEUywGFKi6BE+AFqJOeFsNUfN0m+HsH+rd+NC0KquipUT
         db5Gr35BIvNfLvrgEOW1pGQErYmuNMbySCJXU72sjBtFR53M2aMVPhX6rsTVuoWASsOX
         VpnqQghOPsL7cNAGIhTbf5cpD+iu0Xh4hu4y/Ryu0g+FfjoXv5OYC6T6FylELc2I3bcH
         vllGI2tcBo9JckD6vdMSbmyFh8B4tD8vUlePUw2gY5slMDvB6/Uh9jcFE3Fg4LdjaXIo
         3Nfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730361317; x=1730966117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7igFyRz1Em4vqLMk1CGIR4FjEz17i0UegyNILfzCJjk=;
        b=WhzwMBa5wiuzNoZwxuZgpCw81ZPx1oOqHiU+3VZoTtnVO8OoAz/b19osdXjr3FiQkJ
         oBhIojWrQBk3HKn9Ihf8b9XluiTXYRxlnWrboMHC6HMixjL3hQIdtJ4sFKRh6ZB5nW3E
         4w19ndqzS/QR7BbArwuHMxsnRzMjkejfLn+OnXlKDg0QN2ZHYgSu5vDk5Ppv+ZOcwZBN
         sgOXCaGv0M7rhzyqQEjdggAYbb1bjN2svr68nGWNY6FEaAp3uhXj//W3kSkYCdbdhoK6
         5G77oDwC29atX/RzLhEnRSCJTCgqDI20KOrQZLxNHnWO7KKLn7YQcJHFIiMyGE13iRwj
         cggg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoHp/vAlPFXQ7/GUfz0JLnOp+8Hfso69/IqVMcb898+67JwFe7ozxcWUA4EmQ+zCsaLO/e4g==@lfdr.de
X-Gm-Message-State: AOJu0YzOPGtf8BBLfP6f+7zgsqb7qLMuU+Q/Eqa545R0C+4dv4H/PjUg
	/MpBC7A185Joto4FZwJA5BmO61HF1hafEmuJYS7ChnY8kOTN/NEO
X-Google-Smtp-Source: AGHT+IGDMvjV72V/Auet8q0UShFqx2Urojb5ffRDr3xgbSDRZPoYVbIgzIDMOfsDZcmAWzgy7TuBAQ==
X-Received: by 2002:a05:6000:4009:b0:37d:453f:4469 with SMTP id ffacd0b85a97d-381be7c7931mr2062242f8f.22.1730361316338;
        Thu, 31 Oct 2024 00:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca7:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-4327b817372ls508255e9.2.-pod-prod-02-eu; Thu, 31 Oct 2024
 00:55:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZg+JbUqN8IO+fnOdR0wchkdT7HKfhin3CNHB7XStzrOG4Q7uycpOJB+L1ZYVvAQs1Ny3PhmkysHU=@googlegroups.com
X-Received: by 2002:a05:6000:2805:b0:37d:5173:7a54 with SMTP id ffacd0b85a97d-381bea27660mr1338226f8f.52.1730361313609;
        Thu, 31 Oct 2024 00:55:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730361313; cv=none;
        d=google.com; s=arc-20240605;
        b=hUsIbDTTVRM15WVOHQQro3NS2mhGPaWEJMq2IAQ1C1JI8fDNtXx66Bof5LVHGv9P1/
         nJfWXHHgUZ7r29NALi566SBw7AK0sd9xH/b3qHB30OIST7UfVBkqakDhVTwMT4B9dtL0
         lQOQkFoF1N424f4Macz10RdaA7b8qmDxr+NXp51f5v58YB5uMNciq75gdxVxwp7gGFAw
         sBx2HY8PsHERtGGVkwnUJGFbP8QQC/5x5AsbZUcwZiqKWemAyxzyPqYUbP80ojR/JvVQ
         2aZfekXYLM8+WqaVO0nhf/0fpiO5Zi+mWa84z9dhwtD1BwK7bydsw3zSxjd2c8ikVRIq
         V0HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=smZJ3gWMsDVgdSzoTnaukuVPFfiZhLlX964GA+Dzwz8=;
        fh=jmmlaFYkmflS84vcschwi12fG7wBmVuTslMeBas2QCs=;
        b=b0P9VOjiTORcDly3sTCyobUuO4Ucuqzixt8Ph0DDHuMftDySZED0BqjlZHTx4iHFsb
         XtB6/Hlkpu4xRXwAf/DCO7nnhAMhsEuFNm/bJd4hmtvVc+BOazH3niq4Epxvnxhs1IGh
         7hM50nX12ipelqVjWhYebC7qbpX3GbGvyQwxeZHNQETTp4u4kDJpYPpTafHZcFwmdhr2
         Mlm6DiWg25VXizhBOOk3TOhzA8974QJMtjDUI0J3prngkNtK8YaX8prvpqa7EFpY2ld5
         DNh9o5uFHhGpI18X14MI5dmXyO5UMKcGiq3CjqcHXxxY9LGoS5Y6mbnz516dnhLHmHkG
         y5Kg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=r57rkDgx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431b43a99dbsi4170495e9.0.2024.10.31.00.55.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 00:55:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Thu, 31 Oct 2024 08:55:09 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, boqun.feng@gmail.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <20241031075509.hCS9Amov@linutronix.de>
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
 <20241031072136.JxDEfP5V@linutronix.de>
 <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=r57rkDgx;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2024-10-31 08:35:45 [+0100], Vlastimil Babka wrote:
> On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
> > On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
> >> 
> >> So I need to avoid calling kfree() within an smp_call_function() handler?
> > 
> > Yes. No kmalloc()/ kfree() in IRQ context.
> 
> However, isn't this the case that the rule is actually about hardirq context
> on RT, and most of these operations that are in IRQ context on !RT become
> the threaded interrupt context on RT, so they are actually fine? Or is smp
> call callback a hardirq context on RT and thus it really can't do those
> operations?

interrupt handlers as of request_irq() are forced-threaded on RT so you
can do kmalloc()/ kfree() there. smp_call_function.*() on the other hand
are not threaded and invoked directly within the IRQ context.

> Vlastimil
> 
Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241031075509.hCS9Amov%40linutronix.de.
