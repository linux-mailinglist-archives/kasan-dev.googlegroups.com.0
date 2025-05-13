Return-Path: <kasan-dev+bncBDAMN6NI5EERBRPORPAQMGQEADOM4JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C00DAB4CE9
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 09:39:51 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-30d8365667csf26332191fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 00:39:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747121990; cv=pass;
        d=google.com; s=arc-20240605;
        b=UF5EbhIxjK0dkvLWuZ9ZaB45pa8S6IUa9sc+Z6PGxP0dzAZuQV+CIQLjvLaNDHo68w
         +Z7CqUz8uhdPyS/olHGj0BZQ5Zmw0gQ/UcLfT1VVM5GEFQwY4Hxuyv/+FIMyRkHdZDAL
         7fhKI4MB2+UDodrAs74wDk/iTNwHrTY4QgPGmnCjwTfmn+yqkc0BeYkcuf8lfhzOaB0l
         PT/5uuwaSNSA51jud5sA6THNYKYZQws+3mGTVO5ULe+UvptLCSz9GmIX5HbphTnZf4T1
         UYGuSoSN/n48krHpgSwf27F5OqjruQoItExx8BOY3XUxIlZvlDsXF0CrF8MdZaUaBm6P
         pqRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=/Wc+9Kl5iYgifoRpcr7PbYEoENvQUrsoygrmowPgjMU=;
        fh=Czj15JJZfbpUEzy2if4skAq+Nv633R1/lvmjxHnCE8E=;
        b=HPKEAOtjMesp9DpNqGvq80TWmrQROdA6ezlpVEFrAMp62tm+DlTRmCwFDy/8qrSplQ
         E51TRCWdhvuHqNzrVROQPaXApHtHtOsnXH+/y1tIVnJZ28uReSsniJxxYXGY3cmFFcLQ
         EGoOz/9wRyvDIob5XjlyTW7anVJqeFha/eAar1ERNaxAV6yWBqoH2mWOsqJGJaHypBDJ
         1FyKQb5rAH8OfyG6LwN+aMj/YMuEglKh6BIH5GMfvaPkXqzD02L/6cTpj4FjWSY6RVhz
         aYI6J/ihstkU1JPOndWhoVUtfFyqK1S/t/jFOIEJSfWxeFQCO1GGeTMmmjZNgypbgqYS
         Z0Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=DVjBMxid;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747121990; x=1747726790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Wc+9Kl5iYgifoRpcr7PbYEoENvQUrsoygrmowPgjMU=;
        b=jJc2RL6pGasjIaY0fe/WBjZdRe4ZDBrQuO9uNnzaq6aiBaOk2TN25SbfI9Z5YrJ4a8
         1wftNBRMpoQy6uXkaEO/UMY7tKBFrShqhJ2V0dtCJiVDo/JguoL/QF5SaF2nB4W7unId
         GIj+upd0A0I7zOSkQCvL8Fi29IPmtFNgLM2EAQJ+JqJ2/q0mJORb+tMsBBDae/jTEmZb
         A4BeRlBbgqmX7p2UPyzmgGvxsHQQOkg1z1sY5iUsX6X/hbnMOMPD4MCMGMErLeiJ01nm
         Y3THo1pXbzxsU8IAX1YvPJ5RUtBxn6Khacf/opFXIm66y43khgvSOVl051vNXReOZuMD
         BTDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747121990; x=1747726790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Wc+9Kl5iYgifoRpcr7PbYEoENvQUrsoygrmowPgjMU=;
        b=YmW0Qp3pAlmlmMtwkHg8vac5bVkT3BQlTiLlL3zRqpm0zUhCYnz1LFewk8ElpI6cGw
         h8/ZWYguMfBv7AXJnXJvPNo4IzLkCmaJ9IXEIpOhDr61RHd2j0kv49Q5bN1CtqsEIBMQ
         kwmEfpb8VaE39vKHuMv+qwdqC2JuK5gVeza+F1kfynG0u5rqihGFoN2f4n0+Q6uDLm1P
         gWRyyQey6Fd5zbWfbvCsvnsvhp8Y4s+gE1ZdTPXFO3gzwXKGYhUniEf2BkO/jc2HyGY1
         hcoSOAh94SFuiaYAeNcmiUKH4RBqBc8hNeZJkQvQuh9Hs+3MjBoLh5rODCrydyL9cb3/
         Wn+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWes1fCyr45+SgQ59jsztMqUoxNUgcBzj96jh8/fR40ACl1W8+R9pLgQAThDNTie6T5PPCJ5A==@lfdr.de
X-Gm-Message-State: AOJu0YyI9MJrHMlC2Gj/ZXGiFU4SVD4k7GElFtyCejoZ+2/HrgmZIPuj
	KFpVxPgnu+taoACRgdq4/8k/I2R7LYIQKzMtkypShnDSftvqnkf5
X-Google-Smtp-Source: AGHT+IFQjoBSVVxHtIF36Zoyh9MUfbUVT06NM8BUShJlL2vTkywRLORI5RvO/SHARvIb6EvixXoGiA==
X-Received: by 2002:a05:651c:1472:b0:30d:629c:4333 with SMTP id 38308e7fff4ca-326c46c1b00mr65650201fa.34.1747121990006;
        Tue, 13 May 2025 00:39:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEJuGCXDsl0rGiPHw53mhJqWW74+cIXdvYY/+jgeSkHiQ==
Received: by 2002:a2e:980d:0:b0:30b:ecc4:c33 with SMTP id 38308e7fff4ca-326b67b103fls677191fa.2.-pod-prod-01-eu;
 Tue, 13 May 2025 00:39:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUunTCmeMc+2T4ayYJUSxmsFAF/0CqRbLUp8gX/0P0MFTo8rFiI2D+0b/IkndOouRHo13RUw90QZ1M=@googlegroups.com
X-Received: by 2002:a05:6512:460d:b0:54b:e70:3647 with SMTP id 2adb3069b0e04-54fc67aff30mr5502481e87.7.1747121987431;
        Tue, 13 May 2025 00:39:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747121987; cv=none;
        d=google.com; s=arc-20240605;
        b=OvwlIYmE5zeawVmpgeqvwvqyrFXKOUX/pIFBdf7KCHX05J/W4B8ydeIbP/lcdsQl4m
         w/8/n/wGWkKYu1hqFPvfLbdm8egIms3M9tKYadwkVee5kZLNgfW44Qry6MnDfyteTbXr
         3fxXTSrNpC0sKpM8RJC3ePCqTbEvm6vj/slzAmcSRrX5fSgwCMerVpKw3rmpTaC2mZ9q
         0ljlVtdV/IctpXhzFq2c75OL3P14tr6/Jri/57x+sh4uPH2rQ0qqBxbBqLISmm5y4QYz
         W9YbYaCCaVFGG4groYhZ1mHV7nm1Sv+KEeHhn1c/o0i0RkOZXtEoSBwac9bqzxjFLVA7
         WX0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=AlNVEwGL4cI2wJsUZRWNYyvdArHzwAhJF0ypQd+HF5A=;
        fh=GwQqCvxHS9c67u7PlG+Qp3XED8Vc29u/PceNIUmpg/A=;
        b=ZauFKUVuJe7zIhHsuvzyo/R8aZLrLkDoQ0JqwSU5LIQaAdYH1oxjJU64OtejBF8qRm
         wICRTUDpB8zilW+M+u9GdpOgMJPpwf/cKNGyQ8zzkU+PL8ekrP4wICK43L26Iea9x4Z3
         VyTNizp/cnYMZWl33TZHbY+XOF0tvClQOMiOyzQtay8/Ok7mhjJzdcfeic8wGGgWl0Js
         E99f1Au0LAEkZctQiMk/1UXoVoxnPv8Z0nHs4oF93byYqre2gYAJGdhpct0UzXUOpYnO
         H4+G4CKF13noRiGgzVO3uCtBxtRLvIDLA/mQ0rb+VX9gG3mxb6NUqfys6EzgfVUisRVK
         GZbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=DVjBMxid;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54fceff6ffdsi183322e87.5.2025.05.13.00.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 May 2025 00:39:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org, Marco Elver <elver@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Stephen Rothwell <sfr@canb.auug.org.au>,
 linux-next@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [BUG] sleeping function called from invalid context at
 ./include/linux/sched/mm.h:321
In-Reply-To: <a5c939c4-b123-4b2f-8a22-130e508cbcce@paulmck-laptop>
References: <a5c939c4-b123-4b2f-8a22-130e508cbcce@paulmck-laptop>
Date: Tue, 13 May 2025 09:39:45 +0200
Message-ID: <87o6vxj6wu.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=DVjBMxid;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, May 12 2025 at 16:47, Paul E. McKenney wrote:
> I ran this on x86 with clang version 19.1.7 (CentOS 19.1.7-1.el9).
>
> See below for the full splat.  The TINY02 and SRCU-T scenarios are unique
> in setting both CONFIG_SMP=n and CONFIG_PROVE_LOCKING=y.
>
> Bisection converges here:
>
> c836e5a70c59 ("genirq/chip: Rework irq_set_msi_desc_off()")
>
> The commit reverts cleanly, but results in the following build error:
>
> kernel/irq/chip.c:98:26: error: call to undeclared function 'irq_get_desc_lock'
>
> Thoughts?

Smells like what the top commit of the irq/core branch fixes:

https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=irq/core

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87o6vxj6wu.ffs%40tglx.
