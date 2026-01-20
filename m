Return-Path: <kasan-dev+bncBD3JNNMDTMEBBUMQX7FQMGQEVFQCQIA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eLD7K1PIb2mgMQAAu9opvQ
	(envelope-from <kasan-dev+bncBD3JNNMDTMEBBUMQX7FQMGQEVFQCQIA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:24:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 501BB49668
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 19:24:19 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-6610d8df861sf8214940eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 10:24:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768933458; cv=pass;
        d=google.com; s=arc-20240605;
        b=COI7DS3INnK0sQJJgy6JwvG3m8eiF2tHIXg/YkF/jchlWPgKub4OsGC9yB1coiraQ/
         nYHvbwz5WuXSTejvjOr5LbzLFdMqDAI+Sz2Z8j4QATftgzBCM0NkMcaYao5bsNNnNM4K
         +W18ARSMt4D5EHbykqg4NlwfhbVJ/iS2MafD3d7lofbm/Vo3durAFaqogWUqYW0gqZFP
         sCpx/fEtSxZqvYrsnoBMHZSIcTGUkMmWQbu+0vnD8VjnYgmNHRt65GChzaH7XZ9vsNT9
         HbFRBrAFKcvLXnrVrbP42U9scSdb2GmcjoMJG4fyGk3rMcY+/ZvlTbjwmxulX60w1CEj
         M2jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=22KRk2PR5n75oF8aGxe4LxskggiGGn8Jx/t3dRyURj4=;
        fh=tDPW3MaduiC/qoAjhGrIrKQ6nj1a8JkORcQemXiITRY=;
        b=U0018hHUcG68W3DhACYJbq/mCib5pUkLhICFQT621AEmGSO2OJNbjiUCV1NV8CukVv
         K92p1KlqybWiXH4JT1Q/WslYH9vrG93W8llVI/zZPvWdUzV8fRgXtpqWabM1EgwPKecX
         HRpJrBI94eG6LeUT0FcbDV/AQ0VXHV8731ZGp8uioOJ4juRD4fsMXR8Gt9rNvMH0LuwO
         +impxXvioJ2eQV+eoPaEbTx3+jdYr/H4/NbYPmf48BzWqOe/98dbfFZxzvQ/WI50q5Ls
         lI6aNAj0sWx0lGVHOb4fRz1p49cmkeg4uYnc90MOlpMG9AwR48WaZaFqMrg1Y6k21lED
         vkRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=AqUY9lXl;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768933458; x=1769538258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=22KRk2PR5n75oF8aGxe4LxskggiGGn8Jx/t3dRyURj4=;
        b=EQzRcMja4gfV3UheG+8RGql/6p2toIgwmY2eBIR4L4vbAzrO1e/Z7ivpHBGfZVul/I
         xoRCbsIQDfnEDz78dbH0Ehiaovrw2f7BWrlR9bTY4/1s3NSkFZcUsb1qkUhBtGYWe0Ar
         R7Tc5ie0j68O5AEulA2Rdh+NbOv3QUBfkKOUhQ38vcw8BUMmtB3eitJj6YTepKXdC27e
         iLQXjV4Y/lssdI6bo+rZ9QEpq/Yo9RhNbGifqNMibejL7cqnlnRFllzuTLCHXkTiNrM6
         f2eLtw7I0kmNsXgROEOcEKB6/4c6Se31SX/dffvtsf2TQydix0f2srRt9Zl+xl/JwJuN
         WDqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768933458; x=1769538258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=22KRk2PR5n75oF8aGxe4LxskggiGGn8Jx/t3dRyURj4=;
        b=jJ6yKx2DSowrgZlSEaE6J8VmHgc/XN2P8SoR0pr+WfZW2g/FEscVBB7bvmebUpTdeN
         ZmumTrgM9F1s61aspmujiL3xnz2DoElWSTN1GOCKDWN3NZJ3FGBGmPbeyPkwLE5G/r/Z
         WdCDKo2MGcKuuFOr2mrtGzfoxwoUNowXqDHJRfvDSAcF94OKOuTaSbauMivJzd8qdGGA
         VVxLhQ8pn9vYvFtKVSc13ourdUzysbNq40p3jXJX/3CwgGV6n4Eo4dik76kDHXSRKdAt
         wDdeYj6CPiRlwIlFr3690ouANA5RUIIoT0msXrMALMLW1p7XiSj7Ys7GPJ/hA0+/Y/vu
         kTlA==
X-Forwarded-Encrypted: i=2; AJvYcCVDzoB/xIiQXlapAqyfDG4zCADBWKpc0ceQ3nBvFICc3faSGLv825cgmsV52G3Kyal+PJz9hg==@lfdr.de
X-Gm-Message-State: AOJu0YyNDYNxuDl7uhlA/3Soq37mnvngie2qf89zRgTKNlImyx8y+TDA
	QQ+GK5BsESW2JGSGknm5JpFYDZZqP8CyLQ1MQyfsHFUQUArUX0Yqkp5A
X-Received: by 2002:a05:6820:606:b0:65f:6bcd:e32 with SMTP id 006d021491bc7-661179db6ffmr6048122eaf.58.1768933457803;
        Tue, 20 Jan 2026 10:24:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ED+CzDW3GAhHQDhjU9MuBnrcCgPBe9QEaBrE5t92CyUA=="
Received: by 2002:a4a:d996:0:b0:656:cea8:d380 with SMTP id 006d021491bc7-6610e3c2ab0ls1351355eaf.0.-pod-prod-02-us;
 Tue, 20 Jan 2026 10:24:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXchm7eitUbv4Bna0VqqkpWpGa9KJ1vmN8zPq4STEhZMRv8biXPP4nAuMkdIWJZHzD5Fbt83A2H4hk=@googlegroups.com
X-Received: by 2002:a4a:ba97:0:b0:661:1d0c:a5b3 with SMTP id 006d021491bc7-6611d0caaa0mr4638070eaf.21.1768933456760;
        Tue, 20 Jan 2026 10:24:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768933456; cv=none;
        d=google.com; s=arc-20240605;
        b=OMibq/Aq4tVdQi9w82sGyNZVmONmxoY3Qf10zgiZgF+ihU0mQ6RULOD+pxe1l7aEPN
         ++97iGjrjqLqyzy+NeOHopAQB8ZgY7T2C9715Ymk4Sz6srTPTnFVXcykuy+678n+PVGD
         nZWd+oCsvp6RANUyfu3l9706M2jdlhE8QnDJfawMXowKSx51qotQnY6MWg58ATHontAo
         oQ4r4y15e8B+X1YcO8XEhIxFaBbzgBh4/MP/yT7GGycrzmneIuYcRrbOBbW07o/hxh/B
         1OhLc9pH0qpel/81qZQvYBvXaeajY3m/bis5K+fMdaqvQ7l2gAqqDqOW4XIgWJRJG4YX
         BDNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=laO+s2zBiXudQJg6l9/ECBEXlmXile3qngJMXioXyAw=;
        fh=vlcXSv2iTzSr0h7NzcezV2RbgWzAebaTt1TOXuBx0gA=;
        b=QSkG54JVmd1fzmOEljZ1VWKIpt2o8hisb3g8jW0iF1HoaW6ExUHT7bi5eaJVfW06/d
         /p5vBPO1/55JXlOqWbudKEsRiAi9oVKZEji4NbQfYdGMRSCmelwZkrFYnMgzBgk4WNft
         Sk1Id0KNh/LWKauMMnpr0Ak3SUAMC2X0hk9LMDeoNv/Sw434s3zJH6unVHdHmFtykj64
         1+ZnXXlb8SzrGBTPSWj19QsPmq/+C9PPGb5Zs21LwVZ2Z+5wYY822O2E4erAhcEQkuVt
         nETefrl5CzVSVTTOEBq1ERUhJd+BsV9vxT8DDaArP7Cq4bBLm3DPPKGJOOVYR3D8kMRM
         RSfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=AqUY9lXl;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6628c58bc7dsi382069eaf.4.2026.01.20.10.24.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 10:24:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dwbM41s2Lz1XM0ns;
	Tue, 20 Jan 2026 18:24:16 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id vZGs651jTWFO; Tue, 20 Jan 2026 18:24:13 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dwbLx272pz1XM5jn;
	Tue, 20 Jan 2026 18:24:08 +0000 (UTC)
Message-ID: <16d01754-cab9-4067-a65f-60040ac6d47e@acm.org>
Date: Tue, 20 Jan 2026 10:24:08 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
 Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
 Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20260119094029.1344361-1-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=AqUY9lXl;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBD3JNNMDTMEBBUMQX7FQMGQEVFQCQIA];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[linutronix.de,kernel.org,gmail.com,redhat.com,lst.de,goodmis.org,googlegroups.com,lists.linux.dev,vger.kernel.org];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bvanassche@acm.org];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[acm.org:mid,acm.org:replyto,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 501BB49668
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/19/26 1:05 AM, Marco Elver wrote:
> This series proposes a solution to this by introducing scoped init
> guards which Peter suggested, using the guard(type_init)(&lock) or
> scoped_guard(type_init, ..) interface.
Although I haven't had the time yet to do an in-depth review, from a
quick look all patches in this series look good to me.

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/16d01754-cab9-4067-a65f-60040ac6d47e%40acm.org.
