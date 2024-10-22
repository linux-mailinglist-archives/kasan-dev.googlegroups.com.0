Return-Path: <kasan-dev+bncBCR5PSMFZYORBHNC3S4AMGQEHC43SIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F04119A9655
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 04:42:38 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6cbe933e877sf19490216d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:42:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729564958; cv=pass;
        d=google.com; s=arc-20240605;
        b=d8/59aq+6Gui4i8Mj6qDeej4wxQxnItChMnBdj6SyQm6gxyCCpzREBxdrGPIa5DoMi
         vkomMHh1pbEmRQGsTu5eRV+LMQccbDlH6jiq3Ll17dzBdwrElySqkxQo8IB7uQnk8pcJ
         q7Q7FfEiqcFFJpBDnG1ldNh4fbsovHKuEbvD3mfeS6vkFarucYlvE96BYDijHuusnz/h
         zLxFZBK1Jb6/V7xMh1CsxYsdvOJIjZZaZbvUz4OLtJNPrZkmtHBxi1c6JP/tl9k0iiGu
         gPUKjFJwt1FFa81GsKT0/0vAAjcjGwTRRtRxIVUZF1sL46vANUd8xgg/du2LILJf8FpC
         EHPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Hj+4+1tvvuut7uHOgeXIUmoZl6fKFfzRvsEIK/rqK0A=;
        fh=Tgf6q2TEdiJJSPsMyiniF9A7JBQzo6SbnqAPX1kyUwE=;
        b=WuWvD+luvr2TSfZ4Yc0BYP2WpFraSvnU5jk32eDKO0vZA/htbBM6zXYlJu68LSFJM3
         Kv0z12e2/EvCYVSFwU0Hh6cGPBWO39yCdI+256Y9YG/murRXYNC93BHzl2nl2E57Rdb4
         PU7JRPdbFRR6Sf3JOCmUvWk22CsPjIMv/RaKrSlw6AbDek8JmiZaMNA9njtahyh05kl5
         AI9L/5oFzQlQVKTunZuLGITD835q0LEybKKT8XM8qKeBPyttPBu/rFJhmCwNpYLsCaj4
         bYp6NecnlD9h1PQS8kKw+Ppl+ff4X5GXbA406W9SY8/Xg84hx6tQ2jVBQ2sbfVK4JYgR
         bQvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=EpboXSxj;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729564958; x=1730169758; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hj+4+1tvvuut7uHOgeXIUmoZl6fKFfzRvsEIK/rqK0A=;
        b=MwtbNvDSWCHQLn19qfDgnxFXxrtbJMLdeWhJlFgpQBvIZaDHOIVbbRtO/ZVA/4Yzzj
         i+VeJ+/sfRDD2TW6sAgXIcveoSj3KM+9vFkLUC7t+ppMk/OQ7jc14KIL2wBD9NKk9/qq
         sjzDWnRsGhmY+ouwELMPf2AD+TN7+Y0eTMFFMCfdALFzn6nmCtZloEeZZBZvAyQ80y5l
         wgah+BGci2AFrj3pq9oLpZ8NC6d9aIxzW+MdDxY8u/QKHvqa+mC7TGcEVpn87YnZ0e4v
         tOR/H0ou6OV91MVrvO1bUdcG9biMElzHElxUxA2bsF+lPUuMN7hW6q1cmXT0nbPxneSv
         sBlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729564958; x=1730169758;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hj+4+1tvvuut7uHOgeXIUmoZl6fKFfzRvsEIK/rqK0A=;
        b=PXT201XfXQ34XNvUFpRvWbjM0nkUg8vlWlTnG0BJ0QTResCOGptr+gbqcvuNGLIaKh
         hr3DfOdztLLpVSmW/HoNPbfizTqmfUhT1Sjs7TwFCZ5+vweyJ9adlTdo3vAhTxLzmnLM
         KRUq9Z/A7tK+osAosAiGsX1y6ZzMilAUW8pc6T0DSlp46CPj2QyqA2AdDbe/egH/0Ttb
         XH7MEWaWB3ACH0WCklPx5iAu+LKVehcRtwV+jn6LsmKjnXhgTDUUxtIpqYqgODCx47uS
         cjTFfYJ/pmPMzMaoZttKAIPrPEIzQmGKO1RuaNSjRRfmhjBM8u8VliiN0123ATwhhwV/
         RYGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfDLk0XGuieX3TbsfHfW0Pm+2ND+6QtKXrjudVWf148LPPTrCAcCNvgOh3yWAli+6RhP/ikQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx057QY26Z3t5ZwUOLHmW0LvxQSCzYAOrbzb0vgORj3zLCGtxLq
	3gZ2OsU0E7+ZCkxstd3KNNTUPmrDbd9viqe9TXODKfiAdFBtJNpR
X-Google-Smtp-Source: AGHT+IHEEe7sV/M5xVBi3B3CVSL7cxvWL41+oZUvvdbQtOVBtYbR4MMRUvMKv3XOXlAkpSluj5qxvA==
X-Received: by 2002:a05:6214:5d83:b0:6cb:8a6a:25cb with SMTP id 6a1803df08f44-6cde1633993mr190786606d6.43.1729564957656;
        Mon, 21 Oct 2024 19:42:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c41:b0:6c1:7c1d:2ffc with SMTP id
 6a1803df08f44-6cc3737b371ls12329646d6.1.-pod-prod-07-us; Mon, 21 Oct 2024
 19:42:36 -0700 (PDT)
X-Received: by 2002:a05:6214:4498:b0:6cb:e997:6717 with SMTP id 6a1803df08f44-6cde15db124mr212323426d6.38.1729564956668;
        Mon, 21 Oct 2024 19:42:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729564956; cv=none;
        d=google.com; s=arc-20240605;
        b=EZXPC9VQ2FegNRglQSkVhmfZzFt05Ft4UF7Rnzm0sZVs3r9Ia4fdPuWBuEBqt6F5cJ
         NgXDbLqUZ0NtXIfTVDWJXwHHp/jRBeej5Djx/aZiAavQ+YeZnx+LAdQqHfASi5102jKI
         btLDBMS2f0aKFLF15sHft1Xqr2qWHfqhzUu4FAztOBpmGC3HnZLjJTE7jyCzWSOrR1hV
         n502uab2Vzv7e2FmhT8cZBgqtxy/qkl4vrSowegU2vYKVRy7SClinHbDYcwCb9lWJgVe
         Om17FAyNQ8F55JLMPlhwclg1gRQ5JB+hYRYfcjfAymxyUWOxJH4RGuOOSC5GLCk36P5Z
         c3sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=iA44515hIjaaXQQmGhGyu/wNw6RcsnRKM1ujfj6qVyY=;
        fh=iUVkGo0FYNar8bShccuPmcDZ7l/A1ULYbaLeygCzX+E=;
        b=R+EqRsXe5BaIQkOrJKLAFAQyTE1SMEW3lcPs+g1mXrv1zWPB5u/iXJUTrCGREv63Z6
         vgqIoz3imiXaGq2amGnIF3TdmlIduGtH7/ZgdL25O+6bMaKPCM826KMMW86mvHRZMM0W
         k/mB66OaiKk0Rqku1kxYqCWAUmaF2pEpQWB3EtLJB0seJemi2dhVGEdhsJHXFZf4Qeeq
         fITHHqF6ZkHMaO9WsunYCaTMkchniYUTz9MUTyJ/WEJPKW3nrj8LPPi6Pb7tcX5cKwo7
         ZX6ZFA5uV8Vk4q7gOZUgrLri+AozuPtFKQvkdyQYwmB2LFElDQujrJW5pJsfHlFVxRhu
         uH7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=EpboXSxj;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from mail.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ce009b6042si1664766d6.4.2024.10.21.19.42.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 19:42:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4XXc0P57pKz4wnr;
	Tue, 22 Oct 2024 13:42:29 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
 linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, Marco Elver
 <elver@google.com>, Alexander Potapenko <glider@google.com>, Heiko
 Carstens <hca@linux.ibm.com>, Nicholas Piggin <npiggin@gmail.com>,
 Madhavan Srinivasan <maddy@linux.ibm.com>, Christophe Leroy
 <christophe.leroy@csgroup.eu>, Hari Bathini <hbathini@linux.ibm.com>,
 "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom
 <donettom@linux.vnet.ibm.com>, Pavithra Prakash
 <pavrampu@linux.vnet.ibm.com>, LKML <linux-kernel@vger.kernel.org>,
 "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>, Disha Goel
 <disgoel@linux.ibm.com>
Subject: Re: [PATCH v3 01/12] powerpc: mm/fault: Fix kfence page fault
 reporting
In-Reply-To: <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
 <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com>
Date: Tue, 22 Oct 2024 13:42:29 +1100
Message-ID: <87plnsoo2y.fsf@mail.lhotse>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=EpboXSxj;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Hi Ritesh,

"Ritesh Harjani (IBM)" <ritesh.list@gmail.com> writes:
> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
> /proc/kcore can have some unmapped kfence objects which when read via
> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
> functions define their own fixup table for handling fault, use that
> instead of asking kfence to handle such faults.
>
> Hence we search the exception tables for the nip which generated the
> fault. If there is an entry then we let the fixup table handler handle the
> page fault by returning an error from within ___do_page_fault().
>
> This can be easily triggered if someone tries to do dd from /proc/kcore.
> dd if=/proc/kcore of=/dev/null bs=1M
>
> <some example false negatives>
> ===============================
> BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
> Invalid read at 0x000000004f749d2e:
>  copy_from_kernel_nofault+0xb0/0x1c8
>  0xc0000000057f7950
>  read_kcore_iter+0x41c/0x9ac
>  proc_reg_read_iter+0xe4/0x16c
>  vfs_read+0x2e4/0x3b0
>  ksys_read+0x88/0x154
>  system_call_exception+0x124/0x340
>  system_call_common+0x160/0x2c4

I haven't been able to reproduce this. Can you give some more details on
the exact machine/kernel-config/setup where you saw this?

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87plnsoo2y.fsf%40mail.lhotse.
