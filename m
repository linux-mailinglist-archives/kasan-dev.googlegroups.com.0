Return-Path: <kasan-dev+bncBDW2JDUY5AORBAFJTPBQMGQEP637JGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BC89AF811C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 21:05:39 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3a4f6ff23ccsf69678f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 12:05:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751569538; cv=pass;
        d=google.com; s=arc-20240605;
        b=XHjB7aDFDZRF8ic7flqlpQb1LNVgHyfv6k8GIqYvT/tP5dvBFd9s0pC7hoaY7rStFf
         m3ny7UncnrIoaynFcOig/DNpga/48Ze4prmqj6coduKbt68b1Psm9Dgx6HJeKGPqCy6e
         KCdwjj5AzXQm0/aO7wIUzYtV+t6URwtNCAsjZneuBQHc7tk8TGYhoWy044Nxi6l7Pe5w
         c4y7xDagcI0++hXVlJuoQP+yyxs3xllpnBOaQ2e9XEfqmCjmpqcqpil3DgG0Ms+m9Z2q
         5xFEPcpR2bQHtWyEPV6vTjAaSn8Y45xVgrKpxdRMUWLHWKeMbPZSX+3L0akObp7YpIXp
         A7pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=bDgi6wKtGnhzIuiya/hQ4P5yAf7F3XlPyNHleZ64kxY=;
        fh=15CjchEZG7TZz+3TnuAnWTU/LnzlIzedDcB5kxtdMpk=;
        b=NnYLEVJTcPM4Fz8vMoKuE6G++902y75a7nIMuEYBnIC+R+gQxNztjErPE0GqLPCIyL
         uWeVsG+fztHHX9AijFsmqcOxCJGodx1B6RbGHndVuMq+J6MYTBeViRaTYUHP7ZUgjmEF
         Xud6Wi7qRNkSybn5sNzD4vqmvfN5zBrpdCkzN6duVSMH5D5eX8ioCFwQcgxamAwi51w6
         56jbBP+Dpn5fYXCeqC/kntRtvqNrpgpxhhQGdaJBkhTp+fyyxE5GLj+9/805AUEOcxoI
         YFjRKYYT8rsnlD53BejFK8QzHfWDT/No8HtEhD+/nWfrB8ajfnmq7PgOYPCRhT8P6iSm
         OAsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P9WYmNUN;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751569538; x=1752174338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bDgi6wKtGnhzIuiya/hQ4P5yAf7F3XlPyNHleZ64kxY=;
        b=waPNJsKYL7zSDaCHqEgp2Auyn9CMcG0MYs70Z6/0ueAImMqihlVgIpJw9K426xkKS+
         lFyy1Qt/u2jQCEwL2i4MifwnICsGsqzgv/iIoytfLDLyhsOla/uzNISBpFkfqzR9MBer
         83ijmp+9Wfh5sUnEBGH89b89/Y9setKjMKtaPbwTQ1/7gngpf3aybwqnrB3F3HjtFbAD
         NElpjvITwP/+4Es/ce2CbL05++jZJdTcDzlxngTRdZ1diq5G/IWO+04gxq/dW85eigiZ
         Zs4u1kSvx0KIKALetffL5Aq1D8hA00IVqKCGNIu01IpZR2KFZi/cwXLJtIDIgIAPLUVg
         nhTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751569538; x=1752174338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bDgi6wKtGnhzIuiya/hQ4P5yAf7F3XlPyNHleZ64kxY=;
        b=iRIoeuodWeqGiYLzIYihkFR7Ub5hPV9WhQFvMbp5uMJffSyfvifYkaeeMFAVTzYeV2
         4KSzRRD/vANIiHXRSenJOKLmOiIWlU2rbLmWe0p+pTP5uuMiZ4rR6sD6N08eSimOsyDM
         9bdKtA1MtftlUkP/SgOqh1AqBXfwYQJJEAedAnr5YWYs0QdHu5z2ryZClgJOfMZbR6mZ
         Hsh0LEgjBfWyvJz863QV3bJ9aMG4NgHgumV/BdH7B4HGOGwfnR8EJ+Qat4N71oXaYeD9
         SRKaKwfsRfJsQd/0Hbiaf0uKhxKWw+MlIrBXgzvvE8nM8mgcYNo8XaTT+2oOwbOM7AwH
         af9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751569538; x=1752174338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bDgi6wKtGnhzIuiya/hQ4P5yAf7F3XlPyNHleZ64kxY=;
        b=PDln4SdaWUC0KSFbe3VXfOJQA6FNtPfVboLetvDtdiULrgT1Pt9Mps3PNZfKJDUVYI
         m79REY2i/tVjEYucisIw9K6t7hjIX1EGoTlzca6BlP7bAdK3DwaC/DnliMK+BdyfgsE9
         yDNoZyBOStl1VgIdpxL0YNUdB1w5QnMX9xEC+gic1Sk3M1zpNJlF18U2v/ZkXq8axYbt
         +Ve6275+PXQQRw258cO6qbcSVveNcz6ZpSwpg9E0vvQMGN32CgiV8Lls+CkRUeVfqZlw
         9F2gfP4XRoI3rzJWp3tD13esO8yolEww03Ft6o9AlOpoYl+ck+/KZoLCDp44gBTwzVOJ
         ERzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOsihVj8vbUuEUhCv4CEKtNgKY9qk1YMdUc38OW/XRlZceyrqgRR+fUsskxK2g9DG1/4GH0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yyo5y0HjmkLkuXVeHjspIN8+ugFoGNa8LCvoe+H7pqxUYakeoGY
	OWznr1FNK54r4Wx1iI62+SrXmC1cbvZ/TDUAgUHx+XZJZg9Tm46Eoiwo
X-Google-Smtp-Source: AGHT+IHjVzty+Jg6ElaDmdwqa9s1+lT++SpUZKyfOscjB0reehgnvNnY944YL45Qsh44ADistFIvSw==
X-Received: by 2002:a05:6000:280a:b0:3a5:39d5:d962 with SMTP id ffacd0b85a97d-3b20067c8e0mr4458890f8f.41.1751569536658;
        Thu, 03 Jul 2025 12:05:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeOgCJ2uWmuWisDqDQJuTmEMMnUQYEr4GI9otwmJ9uLtA==
Received: by 2002:a5d:5d10:0:b0:3a4:bfde:c058 with SMTP id ffacd0b85a97d-3b470027cdals2081f8f.2.-pod-prod-02-eu;
 Thu, 03 Jul 2025 12:05:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLdTAqNsIDbGv6Ocx/ILo3oEyrXACUnJKSwW/DlQel7Q3g6WTfk2g69grCr+DPuAckGoR2in8ZYl8=@googlegroups.com
X-Received: by 2002:a05:6000:2891:b0:3a4:f7e6:2b29 with SMTP id ffacd0b85a97d-3b1fd74c986mr7548332f8f.5.1751569533781;
        Thu, 03 Jul 2025 12:05:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751569533; cv=none;
        d=google.com; s=arc-20240605;
        b=D3+uhTtu8u5q7FLXzTQfdv+p+mz/jR4VsQcbocj2EbH7dwqpSg9+1eXMh97QNILqL9
         3xDgxoLCqOkArs4ULqNI2Pul1MfN1gNfx5HFfj+yd8i2eVqd+Wp6hbQWEBVMfqMjQn/q
         GqAzzz8W+yrCdOg3KTT9YiFhtvVOHQ1nTm+cCFZSI1SE1YvQkuoUZWk0rnq65dgw4BrG
         48Dh7Z0JQXcGqTPOUPkRSPJ5IwrBoryvSwTo5fSPHpWvW0cZ9/TyejWD3sQ2IIQ273SF
         zAiTk055OvRsB44G2PVxcS9QNS7ryfFdDeKSYRpgwEAqgqC1XcwK6hs1dKTCAK1oH1fE
         i7Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eEes5oE48jiUB+IbTjNoonD0N5PundEhMgfAv/RRt5A=;
        fh=PEGMj5vSOA2q1fJG/xr0ddpeCj1+n6GSxK2kNJvD8bM=;
        b=kwekDlQUtYbJOmhEj3bPlAr+U3AiZzaf8g2iXozsBdfOTIpnXdQOloFVE4wAGiQobF
         3S9ODEck9fGbGOeXai/gLHXElz1JNLJswTwovji8xv6ppADHlLUz6Ai86AeTYMAxozbp
         nAevyhChH9eSh3qzrp7dT9Eeaxb1piSybmHvQQ+rl0l1zZRTEs9hcPiaDLWXw1AdBS5h
         WIgD8CoUC7heDHQQZkeo/jsp2GE6MRHWB8Fbw5SON4aV15Dl8cI/6xx7aZvMpaKGfRJ+
         a7h8sLbCu5G/uECLWdvEdkvByiy4rjVb78PE2P2rJmY0hP1UmnF2zo8STGfYzVXMv3eI
         uO0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P9WYmNUN;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b46cff5ef9si17188f8f.0.2025.07.03.12.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jul 2025 12:05:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-3a6cd1a6fecso116747f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 03 Jul 2025 12:05:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9B5anBHU3zZ/1e4HeUgkKC/JaP5oWLh4kjGv+Xg++pSAbomGoRj1jDicoxEWufMoIuZ8BIFJdFtI=@googlegroups.com
X-Gm-Gg: ASbGnctmHt0nqks7p8wFB7mYy4EE1GplToo/bYZwnkq3fxk8WvKCiPDpif8wy75A34y
	V0ipnyVfZn+7QzMls+z5+E1UfPUx2BOACkZeqJZod+bDSx03MYKuFiGmJr/Jk9k5xkTN9otLwFV
	sq8pKulflpYaY1ER1uHvgZd2dl6j/+prFlvNiMilHmgQoFQw==
X-Received: by 2002:a05:6000:401e:b0:3a6:f2a7:d0bb with SMTP id
 ffacd0b85a97d-3b1fd74c660mr6335061f8f.12.1751569531635; Thu, 03 Jul 2025
 12:05:31 -0700 (PDT)
MIME-Version: 1.0
References: <20250703181018.580833-1-yeoreum.yun@arm.com> <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
 <aGbSCG2B6464Lfz7@e129823.arm.com>
In-Reply-To: <aGbSCG2B6464Lfz7@e129823.arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 3 Jul 2025 21:05:20 +0200
X-Gm-Features: Ac12FXyxUbHA_lo-Kj6ls_i2v0Skaq2nx5J2PN_n_cVaHRgGx5xPMKN_AxPcMMo
Message-ID: <CA+fCnZfq570HfXpS1LLUVm0sHXW+rpkSOMLVzafZ2q_ogha47g@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, bigeasy@linutronix.de, clrkwllms@kernel.org, 
	rostedt@goodmis.org, byungchul@sk.com, max.byungchul.park@gmail.com, 
	ysk@kzalloc.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P9WYmNUN;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Jul 3, 2025 at 8:55=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> wr=
ote:
>
> Hi Andrey,
>
> > >
> > > find_vm_area() couldn't be called in atomic_context.
> > > If find_vm_area() is called to reports vm area information,
> > > kasan can trigger deadlock like:
> > >
> > > CPU0                                CPU1
> > > vmalloc();
> > >  alloc_vmap_area();
> > >   spin_lock(&vn->busy.lock)
> > >                                     spin_lock_bh(&some_lock);
> > >    <interrupt occurs>
> > >    <in softirq>
> > >    spin_lock(&some_lock);
> > >                                     <access invalid address>
> > >                                     kasan_report();
> > >                                      print_report();
> > >                                       print_address_description();
> > >                                        kasan_find_vm_area();
> > >                                         find_vm_area();
> > >                                          spin_lock(&vn->busy.lock) //=
 deadlock!
> > >
> > > To prevent possible deadlock while kasan reports, remove kasan_find_v=
m_area().
> >
> > Can we keep it for when we are in_task()?
>
> We couldn't do. since when kasan_find_vm_area() is called,
> the report_lock is grabbed with irq disabled.
>
> Please check discuss with Andrey Ryabinin:
>   https://lore.kernel.org/all/4599f645-f79c-4cce-b686-494428bb9e2a@gmail.=
com/

That was about checking for !in_interrupt(), but I believe checking
for in_task() is different? But I'm not an expert on these checks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfq570HfXpS1LLUVm0sHXW%2BrpkSOMLVzafZ2q_ogha47g%40mail.gmail.com.
