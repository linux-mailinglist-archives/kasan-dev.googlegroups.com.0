Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBDXR5SEQMGQEE6GDRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id DB345406A5D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 12:50:55 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id b29-20020a2ebc1d000000b001ba014dfa94sf713305ljf.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 03:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631271055; cv=pass;
        d=google.com; s=arc-20160816;
        b=oc85E2hE9+FGPOwimWH/hjtsnIwm3K6GPuO2qiC4W9IkE2qUJ5bQHnLHGRJkx6znZ3
         ReoFNs1fsBKaHqOoXn5L7zlpP+cxBXWYyWIuLyzaCfNIC2KoJn/Hmt/IPNAAP6cYPrjc
         YINyWDr+Z9+cqDmRjziCRgBhhONTbiXp88zDqXJe38vW5LHrPzL81inACmmfoN7y0EMc
         3HCNY7klqXE5hN15cZMYfnQ/C4ZINOiMyC7XYHQQzRIOCzY0IwG53Mztqum34zO9bN/U
         90IcFvPKeYOxUmi8Zs9RlSnb/F5SXmdV9dsNrIVfF0a+SVifI9OrRRWHo10NygOmDvIR
         3gcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=1TdAehq+izI6b1ZK8FkrjAMBeVnhbcPMRGp43DOgdwU=;
        b=ahZL+UrtKATwiJ6C/REfQCDVYB/BYKR5niwysFNVlvKtYno7a0rDDXPlz5g5oN1iMk
         au2mSe5Zo6jAj2hPnszHl0YE/3leJtPvvShwdKZKyCqXCInoxDO3mxqZSyg8srLBk7FE
         L5P29YnzUM8V8gBnZo4ivTVPmnRt/MxDxPN+PnLgr1vi8vJzaU127k4WYYmkyq4ApRY5
         f7jRwFq2VYdMUqYm+Dtg+bLYJebZeSmGSzhmu3ZFGIwCcR7Gde0b5UTMk4rdTKnpSwnM
         UOVQV1aWN1a11SNbo6QWGWQojP9ZL3lUKfMGjogvwOxESE69ww9Bl4lPgs4RHg29qk+z
         D2Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="UmM/PXCv";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7h9cOBNJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1TdAehq+izI6b1ZK8FkrjAMBeVnhbcPMRGp43DOgdwU=;
        b=UF4BDw4Firw+5UHC+UlF24GCdbxyr1saYexDalb6gpNdVgbL3emJj139mCV2WwyBKk
         VQqRN06RCBHklYEkp1NTUq0neQwoEt3vjw477RLuMe0TwRkHxALoF2m1CbpzTYaXEV/V
         rewY9Ot/rPplJBIB4HODpO3239Rx3kDu2v5RHopAhLCWo0F74DqxFLTGuS/LLr6YPnlP
         XH8MGqrXOfbHLRB1crvtfjdSFOyo3cN5V3c0K/P8tNPy0hnVzOMnJIeQLA0VcHSSgDfR
         5l1gFR2FIX8XTBNwj5g9+7BYXYcM2ljgr16cNJyF97Q5Ukkxj9IET+IETAKtS5Uu1yZI
         aurw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TdAehq+izI6b1ZK8FkrjAMBeVnhbcPMRGp43DOgdwU=;
        b=Azl7CEy4qDKJ5s0HQN1VO5TwA3A/qq+7GpLjrwFdxAmOD7ja0oIhLatS/qD0OgUJJ3
         to8Bj5LvxO9VtarnzSUy2z5S5W2GvFDNDPF1fUATuXInXWQM+otm19Sxtx6oATwcIwWu
         SSEaRRFU8Y4Ymq9gZgXuEuXTALFlRce3b/kr09uLS/dewqJVptpg8QRZtCKYvA8j2Ufn
         Jgn8lUJuNHTvtnHh1nuNFgPoUDQK1eIAIppwnRvVOLEnmK7v/veASEnJA4WZzAoT3I0P
         Aoa3AuJu4Kiao7y7BCuUh9Z5y0xX8u7HAyhJy+0j2WSoNRBg/JTZJ9DPUnquXxIQALpr
         s24g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ULVXrhfT2I9ngAHa4bdzyonn7rurBRkp/CbTFNymdMF+sJjNA
	fDBYe+uKByVBVY3CgwOf1V4=
X-Google-Smtp-Source: ABdhPJxY6tDpaJ7++ZmoFB1OfTxiwpzD6cNgs2LEHeelpkLU9BhEN6hcVgwmRy//pqXI1zmFyThPnA==
X-Received: by 2002:a05:6512:3404:: with SMTP id i4mr3313694lfr.375.1631271054309;
        Fri, 10 Sep 2021 03:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:13a9:: with SMTP id p41ls2595282lfa.0.gmail; Fri,
 10 Sep 2021 03:50:53 -0700 (PDT)
X-Received: by 2002:a05:6512:32c7:: with SMTP id f7mr3349519lfg.126.1631271053166;
        Fri, 10 Sep 2021 03:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631271053; cv=none;
        d=google.com; s=arc-20160816;
        b=UtRekqzT8b/hXMkHeIGq5s19Ftx1SpllMGXSMYTPAiFL085ZyzfM8O/EAX0JWIKv9V
         cIvoy7mpl2qhrc/KXMp7/pX1rfv78ZYh/xJ5v024M1FRhSJtrlqfuzMNvFp/9LwbWWr8
         ZTtZHYh+IcWAeVgBQWx+vNnR6E+KblZ4IaLaxR8BnjTvAQvBTR5XWxOia0XK2uAzoTYp
         i4Zf3kTrGMFNBgNXjjA1m7Mru/Ig/gi/GkoJvMgi/qLBUjy0XeBfUqLwn0brjyB4AYHB
         f0H5d/u3ICB998CJ7hyPkri2Yw6Cr5Hrl2PMVXOGPEgvqY679lV3PO7cGNWSJQ/20sqi
         FMhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=cLa40tf04nYkoytYOxqmcnFcOjSkFNnyh5QKFWN0cDQ=;
        b=UHsTGqMTDvgGFhfBm597HbcasWawAhW162lFLfbw3Fqvibe73JwvjWBn1DLdPIdZkD
         B8/Zv6UrGTjD765iaz83248SmEeHCMSfnxkXyDzjngDns8uGrCO76QkMCVJ0bwHDAFXt
         qcL/FSGX8JhUYAelWynsTQatLCKMcWoh4n+xHT3rhGyIkVfc4toO4q4YqFAnNxq0XiBe
         CnOSJmfpSHgGczRxnW3CniFDM7kgMF21GJT1kP6IP2CHUwVMogPqint3fh8Hhpj8Dwha
         6OShbV9/znOLjvPNwcUnc0vv1EJvnjDoivUjK7Qrxr349PoiNS6UkEGANCQOycooe/rN
         201A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="UmM/PXCv";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=7h9cOBNJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id g2si378114lfr.3.2021.09.10.03.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Sep 2021 03:50:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5AF9021AD9;
	Fri, 10 Sep 2021 10:50:52 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0B64A13D27;
	Fri, 10 Sep 2021 10:50:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id zunNAYw4O2F5HgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 10 Sep 2021 10:50:52 +0000
Message-ID: <1b1569ac-1144-4f9c-6938-b9d79c6743de@suse.cz>
Date: Fri, 10 Sep 2021 12:50:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.0
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
Content-Language: en-US
To: Shuah Khan <skhan@linuxfoundation.org>, Marco Elver <elver@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 Vinayak Menon <vinmenon@codeaurora.org>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>
References: <20210907141307.1437816-1-elver@google.com>
 <69f98dbd-e754-c34a-72cf-a62c858bcd2f@linuxfoundation.org>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <69f98dbd-e754-c34a-72cf-a62c858bcd2f@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="UmM/PXCv";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=7h9cOBNJ;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/7/21 22:05, Shuah Khan wrote:
> On 9/7/21 8:13 AM, Marco Elver wrote:
>> Shuah Khan reported [1]:
>>
>> =C2=A0 | When CONFIG_PROVE_RAW_LOCK_NESTING=3Dy and CONFIG_KASAN are ena=
bled,
>> =C2=A0 | kasan_record_aux_stack() runs into "BUG: Invalid wait context" =
when
>> =C2=A0 | it tries to allocate memory attempting to acquire spinlock in p=
age
>> =C2=A0 | allocation code while holding workqueue pool raw_spinlock.
>> =C2=A0 |
>> =C2=A0 | There are several instances of this problem when block layer tr=
ies
>> =C2=A0 | to __queue_work(). Call trace from one of these instances is be=
low:
>> =C2=A0 |
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0 kblockd_mod_delayed_work_on()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 mod_delayed_work_on()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __queue_delayed=
_work()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __q=
ueue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 insert_work()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 kasan_record_aux_stack()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_save_stack()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 stack_depot_save()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 alloc_pages()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __all=
oc_pages()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 get_page_from_freelist()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 rm_queue()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 rm_queue_pcplist()
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_lock_irqsave(&pagesets.loc=
k, flags);
>> =C2=A0 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 [ BUG: Invalid wait context trig=
gered ]
>>
>> [1]
>> https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.o=
rg
>>
>> PROVE_RAW_LOCK_NESTING is pointing out that (on RT kernels) the locking
>> rules are being violated. More generally, memory is being allocated from
>> a non-preemptive context (raw_spin_lock'd c-s) where it is not allowed.
>>
>> To properly fix this, we must prevent stackdepot from replenishing its
>> "stack slab" pool if memory allocations cannot be done in the current
>> context: it's a bug to use either GFP_ATOMIC nor GFP_NOWAIT in certain
>> non-preemptive contexts, including raw_spin_locks (see gfp.h and
>> ab00db216c9c7).
>>
>> The only downside is that saving a stack trace may fail if: stackdepot
>> runs out of space AND the same stack trace has not been recorded before.
>> I expect this to be unlikely, and a simple experiment (boot the kernel)
>> didn't result in any failure to record stack trace from insert_work().
>>
>> The series includes a few minor fixes to stackdepot that I noticed in
>> preparing the series. It then introduces __stack_depot_save(), which
>> exposes the option to force stackdepot to not allocate any memory.
>> Finally, KASAN is changed to use the new stackdepot interface and
>> provide kasan_record_aux_stack_noalloc(), which is then used by
>> workqueue code.
>>
>> Marco Elver (6):
>> =C2=A0=C2=A0 lib/stackdepot: include gfp.h
>> =C2=A0=C2=A0 lib/stackdepot: remove unused function argument
>> =C2=A0=C2=A0 lib/stackdepot: introduce __stack_depot_save()
>> =C2=A0=C2=A0 kasan: common: provide can_alloc in kasan_save_stack()
>> =C2=A0=C2=A0 kasan: generic: introduce kasan_record_aux_stack_noalloc()
>> =C2=A0=C2=A0 workqueue, kasan: avoid alloc_pages() when recording stack
>>
>> =C2=A0 include/linux/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 2 ++
>> =C2=A0 include/linux/stackdepot.h |=C2=A0 6 +++++
>> =C2=A0 kernel/workqueue.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 2 +-
>> =C2=A0 lib/stackdepot.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 51 ++++++++++++++++++++++++++++++--------
>> =C2=A0 mm/kasan/common.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 6 ++---
>> =C2=A0 mm/kasan/generic.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 | 14 +++++++++--
>> =C2=A0 mm/kasan/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 2 +-
>> =C2=A0 7 files changed, 65 insertions(+), 18 deletions(-)
>>
>=20
> Thank you. Tested all the 6 patches in this series on Linux 5.14. This pr=
oblem
> exists in 5.13 and needs to be marked for both 5.14 and 5.13 stable relea=
ses.

I think if this problem manifests only with CONFIG_PROVE_RAW_LOCK_NESTING
then it shouldn't be backported to stable. CONFIG_PROVE_RAW_LOCK_NESTING is
an experimental/development option to earlier discover what will collide
with RT lock semantics, without needing the full RT tree.
Thus, good to fix going forward, but not necessary to stable backport.

> Here is my
>=20
> Tested-by: Shuah Khan <skhan@linuxfoundation.org>
>=20
> thanks,
> -- Shuah
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1b1569ac-1144-4f9c-6938-b9d79c6743de%40suse.cz.
