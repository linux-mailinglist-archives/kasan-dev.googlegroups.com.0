Return-Path: <kasan-dev+bncBCII7JXRXUGBBW6CR3CQMGQEQMW76LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C9870B2B3C6
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 23:55:41 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55ce50aa2fdsf2231666e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 14:55:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755554141; cv=pass;
        d=google.com; s=arc-20240605;
        b=W4/XqmXbY2k4orNl7GOF1srbuTdIUv+gRfAW85t8Zi0urHW3crsT7Xy+TxtVluzqZ8
         4oVJCRvkNwQEBP/lqh3qPvYRLcGngaBoA8wOjtPtgzn7w503QFUNBpbB1Pts4fZETmx4
         u7qPQgH8l8miVrt46Det/WF25ww2wG8rgg9/d3dcXOqx4AnCxsf4dVGLwlkA4S4Vuzpz
         PZBW8A7NNxJgKJAnmsJ+6R6cuvzsa2EPJnVCLWL1yH31HgKoGeW+jkR/0mLL88K6a5VI
         CG2QVzmvvIMJSfHqkWEMblTRMzDVeJGy0VYx6oGmn+rno7sV+09fYzPyVyc0Ujyl9Am6
         1TvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=41KL1OzuOEp13bYUn64dTYvZ+70fePRD6EY5oHIXNaM=;
        fh=drhbzKBNb3582tzOe3JtraNi/vGwunFmsTf7mbi2jaA=;
        b=lnmJx32eO0zgT8VPqu98Dc16ZrpalaEr3Rpgz/KY0E20bxOlX3Xz927+1gc4XhzloK
         lx6L0qBGo67SJQ2TPaX0VKurubVhGxKYv+M9XHzCZMtLwr3IcfWMxbyfv+2FQwYE8hw5
         6NJyFisyHDqyDak/1Svr9ePskw/kw1ikte2RjTEn8AfU3BZQTe2EIpBlv1La3Upu/pU0
         R2OQmEFKA+MYkhR+Sdzc1G1PaCEPIZfmk3sNrIAEfAQoasRAFEH8fLFREWxwgs0x+n5q
         jWDzT4LghY1w20YcWWVN8wVKTmVhqJ6esq4Ak/BKvRVobYUvmJZib8j53C6c3G5foCQI
         Dtsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=moSNTz60;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 2001:bc8:3310:100::1 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755554141; x=1756158941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=41KL1OzuOEp13bYUn64dTYvZ+70fePRD6EY5oHIXNaM=;
        b=tUe10pQy23D3NjSB9QSwv7TenGh13AEHCo1c5oIKfZe+8y9UR36I2fBBEMtuXIlVTF
         da+uunV9S1EctGYbqCs1nshW4ZQK1NN/s7Piy7Fa79R9Yko/QgglSs8X18kzimpJuYIr
         lanRjAecR53G4Li8e3ULOcy43D4NhchT+41wNwbAFC8qRD5wnRKyLg+jcHiwBLSNRTSX
         HznAnfNTwifcG4ioiINW/rFjM2naSxl71BKl6GJIed+UOn2+hu9Zkkm7AuLm2St5I3By
         VAkJDFxrI/MEESraaouiP/GbIpAB3bE+YQ+NwpP/VgZvGu2lLMcoPWF5qnbeegexuKpv
         JFug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755554141; x=1756158941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=41KL1OzuOEp13bYUn64dTYvZ+70fePRD6EY5oHIXNaM=;
        b=s54486OUxXE6aAfUFR84s6UD8shRkHUbY2pERqb3H/sJOQ5CGeGbPtstFwJ5IUFOSm
         5EiyjXnzpx3zgMo/rrs7Up5BcLxC509VLGhT09xE9MxURJr+Pag1R+7dNjxAGAQaT0k5
         hOGjwFUGLOxfd3hdxdkR/If4kslhC/GaEb+a/GUGFtHAgLYFxK5/fadRvS9wXblJTg97
         Jpc5y1FTnB1IDrMhXLEhzqRjvVTKRa3hHK1IBzbOyIeltbo9ca54UFKneiQ+OV0bhTrZ
         Qw6VAA7nU7UUsB9CXo+clKL165xpQSTFW7iJxSpI0j3Zte1d+QnFzNHsyL8Or4itKYge
         jCOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUV2JMVs/aDWqHzXnnnvUvyQn+7IEfOgvtO/hbxoT0RaQ8TpzoHPPaN+LpJpadBb7NKiZp/Wg==@lfdr.de
X-Gm-Message-State: AOJu0YwrsyMEYAKoU9lFiCTbvMI7nqWhkPHHRKm1NbrnMgnPG1CowwDN
	qJ/OS+CoHXPypa+EwymzezdcoSvQ1RXD0opYOWf5I6fu0A4zuDSZgQS2
X-Google-Smtp-Source: AGHT+IEdghExMEaAkPEm44MHFX+gJa/sHP5K8UyYSeEzbufz4GIPLwn7WHKCXqNwUjXAnZ+j1irA1A==
X-Received: by 2002:a05:6512:401b:b0:553:3178:2928 with SMTP id 2adb3069b0e04-55e0076de5emr131961e87.16.1755554140478;
        Mon, 18 Aug 2025 14:55:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcp6XQ5UH7il1tk4T92fuUEgpTWO9tynYwrC6uN7aHd1Q==
Received: by 2002:a05:6512:224e:b0:55c:e2a0:4c8d with SMTP id
 2adb3069b0e04-55ce4bc889fls1338895e87.0.-pod-prod-07-eu; Mon, 18 Aug 2025
 14:55:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJYdzEJGndAf8qSMgFBe54VSxlD1umwMO3FU2Rgo0OvCOVqinCDNxzULMUK0TzX3tQtHgwJgb9gpM=@googlegroups.com
X-Received: by 2002:ac2:4e10:0:b0:553:330e:59da with SMTP id 2adb3069b0e04-55e007f2239mr111526e87.53.1755554137437;
        Mon, 18 Aug 2025 14:55:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755554137; cv=none;
        d=google.com; s=arc-20240605;
        b=TP3joX3egNWB8vdeiBOWLFkEeuhygREKsFFRo/RyTuvU0dW1PxizgI4JbJUuz5tm88
         HB/9SPDr7bZt8qSdv9cdSYaldtx+AroFYUEcoT/FYSorVr9j5zzt9bUxJZjN9gv6eJn0
         juAxxQvd6fH66vB58dezucLIUdzd9E1FhHxOp70QP72OQ76ujsDnnP8mszcm4PBgFbJW
         QOPIcv9fxEc6uEiT4nOWjolM/2S8+34GIyad+kIyy30aPYfHSNIICjMKQYSIqyPQDOXN
         7omrJZoxH9JozZjEC7i607JpgAhjA9s5YqbsZYKY5a62REp1aZE9lEg6OYtMVDPqNjWS
         1eUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=auLOhWoJLzMo5J4E2hQaw+rrZVFMM1bMgBRMGY/PL2o=;
        fh=a0wluWQE0YnBrrDZiIUXjmkbeq8xF54eDQ5kK8IGCaU=;
        b=BSMGZXBsydcqGjTdpr6JE/cP38e0BCCkPfdhovJyW9TM4vTi0PlDU6RMdj0227q7UW
         b+M0k03XSvdpxcKkiXJFOc3xlwZbHlucdkfdAMFwglgZZflT3Y9AWZq4ky+tGmRuu3RS
         cXz78DlheunYcnAmbkrmn6UPrjPMAZKtgKGYmexeIb26MKiRbQkvXvGkce1r7TquB4sI
         G850tglfaaTt96W67ezXO4DGas9YtqIIuLoT1yAtgqCzMSn8EyY7cK6qSsFb+rp17Tah
         Ici3fr6efHHmvviJGLr0gMq4oqpMOvaisAlHsenpyJ0RsJvbFN/fdtNFtviYwWPj/WWh
         dzKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=moSNTz60;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 2001:bc8:3310:100::1 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from submarine.notk.org (submarine.notk.org. [2001:bc8:3310:100::1])
        by gmr-mx.google.com with ESMTP id 2adb3069b0e04-55cf4437ab3si137893e87.2.2025.08.18.14.55.37;
        Mon, 18 Aug 2025 14:55:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 2001:bc8:3310:100::1 as permitted sender) client-ip=2001:bc8:3310:100::1;
Received: from gaia.codewreck.org (localhost [127.0.0.1])
	by submarine.notk.org (Postfix) with ESMTPS id C157514C2D3;
	Mon, 18 Aug 2025 23:55:30 +0200 (CEST)
Received: from localhost (gaia.codewreck.org [local])
	by gaia.codewreck.org (OpenSMTPD) with ESMTPA id 05349875;
	Mon, 18 Aug 2025 21:55:29 +0000 (UTC)
Date: Tue, 19 Aug 2025 06:55:13 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: Oleg Nesterov <oleg@redhat.com>
Cc: syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>,
	David Howells <dhowells@redhat.com>,
	K Prateek Nayak <kprateek.nayak@amd.com>, akpm@linux-foundation.org,
	brauner@kernel.org, dvyukov@google.com, elver@google.com,
	glider@google.com, jack@suse.cz, kasan-dev@googlegroups.com,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com,
	viro@zeniv.linux.org.uk, willy@infradead.org
Subject: Re: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
Message-ID: <aKOhQcVwLd1Kvt6N@codewreck.org>
References: <20250818114404.GA18626@redhat.com>
 <68a31e33.050a0220.e29e5.00a6.GAE@google.com>
 <20250818125625.GC18626@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250818125625.GC18626@redhat.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=moSNTz60;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 2001:bc8:3310:100::1
 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

Hi Oleg,

Oleg Nesterov wrote on Mon, Aug 18, 2025 at 02:56:26PM +0200:
> On 08/18, syzbot wrote:
> > syzbot has tested the proposed patch and the reproducer did not trigger any issue:

(I hate that syzbot identified "hung in v9fs_file_fsync" but doesn't
bother to Cc 9p folks... all the time..)

> Dominique, David,
> 
> Perhaps you can reconsider the fix that Prateek and I tried to propose
> in this thread
> 
> 	[syzbot] [netfs?] INFO: task hung in netfs_unbuffered_write_iter
> 	https://lore.kernel.org/all/67dedd2f.050a0220.31a16b.003f.GAE@google.com/

I've re-read that thread, and I still think this must be a problem
specific to syzbot doing obviously bogus things (e.g. replying before
request, or whatever it is this particular repro is doing), but I guess
your patch is also sane enough and the 9p optimization is probably not
really needed here

Please resend as a proper patch, and I'll just run some quick check (and
a trivial benchmark) and pick it up

Thanks,
-- 
Dominique Martinet | Asmadeus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKOhQcVwLd1Kvt6N%40codewreck.org.
