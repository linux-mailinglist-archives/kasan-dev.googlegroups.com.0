Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBGW34KGQMGQES7WAAJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id DEF0847456C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 15:43:38 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf8890544lfv.23
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 06:43:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639493018; cv=pass;
        d=google.com; s=arc-20160816;
        b=qKb0xHJh9i1ZAxUZ4nK5dACHIYOE0KvcTesng93a/soEziUyuifNf2aTqLassSGAmX
         QDKdWxKvx47R6oS8jVNnQOfio8blh5wIm6l8mC61jc3cRUMUJzXjFAFf/x1PH6dLTMjX
         erb77XRpw9xPd79Wb0pSAnbTx1ISBu17B6sO3Qom+lIshFcpf4iAaBHvEKaW8VbOPPul
         LGEdB99oVOsIP1tI8+LHzSMZcWx7SZHYmJZaNc3WZEXNJAj/fDA6kHTUZ3i6uU3LH9SL
         jz/F688svIXb8buuKtjDybrQjXIoq2lSKFL/a0A78zHRfNeqfdkcV/AYUQ2cnJO/mHaW
         GK7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=SqRM64/rwRwe+oEwPsU3QQQxPLEs1d95UzeB2XqWgjo=;
        b=zxSODK6F2RFmRLFdmkk0y0e7tzmhmBRtFB5HL7p1r5O9mC2I/bGdHcaSNMq7v+moa0
         fSN45TIBiF9+FeryCb55kM7V6FtzAhGMero23WI6B2gZTTO7/nqvxHEYT1/nGnMBP6jS
         CezfGUlygOu3RsgTPo9IVsC/zCFva2Byu5pbdLS//jN2AzAAFxzWMxgeivI3m6mUNWQd
         sClC+0C+6BFW2myK+zfdfyVgFstQU/0FPrcFitXeZGt1n/8QwK1UnRqnFXnUvS9dwOrq
         59nxi8jn3SN8iX4RH/QOavZ/d0CTwzK0RUf6SvYzqsvTrFqItfPSs/A6f9TzA7/c/D6R
         ha+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EA5SlD72;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SqRM64/rwRwe+oEwPsU3QQQxPLEs1d95UzeB2XqWgjo=;
        b=gK7wUhkAx6Pe2S9gT0RAvGSYybRAg6Po4q41eAFFWPa+x6gwKl2R4CIOCjk3J75kvM
         8V5i/4qpurbhXEX9FCrX+kZavKOEHqG6JviAH0Wq6RQ54Sf96fL1MKCWDVOAaZjUZ/sO
         i8Hc6F1rj8m36V2kP2q8R+KBp08D20xqWOQPsGm8HcXUHegWwZROevqsJMhcDIidKEnb
         K3c/RLwtVvprIgE2YFPTWb0140NCfbY4RXxVr1Ma0I9sAxECUG89SQiR0ckcr+gayx4/
         PrfsTdgRE3Vqaksm9/9ez7bG6YNWLL9q2Qs4E5tWB+TQr+GP/AVXEm1OCTkdm3alHhg+
         CjWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SqRM64/rwRwe+oEwPsU3QQQxPLEs1d95UzeB2XqWgjo=;
        b=R5ID7dLrGCLiqbs3so40L44k4RbLLIJjp+75xMfyXiFfHAbAFQ1E3DX5SmW02MM9Ek
         p8YpXHFqpZMXkaoOdSvaS74t640V3MnxXlirCUrYRBo5JvSKCLS8uzWHZIzKO6mgOwzA
         9UTs1by4Nxv59jB6b7GKcd2Us1XroqW8SznqNMjuE8OuSKSaisojzJYRjfJqpO7TXchL
         UfBj2zsADaIF8mSinD5VLZEgo2pANN22PK6gIEZE8YC/0pi+5+NmnXAmQEP1ZB7Uz+L9
         cYmSgWfWFlIFlQ2fXTxUWq8TgEyhX75LCWNgCzViVvRfZBMW53par5C1RnDGKMnEl1Mi
         EkeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533v0ErPZVeViP1InyhP09uwFBPabSk42xuo4mQGs60u81kkPje6
	qA6tjUmEXvOZknMUDiVxKXw=
X-Google-Smtp-Source: ABdhPJzpwP6k9QbcwakmH+HQhaQk20o9tRAN+5sb/EJJDsyzm7Afyt2MauFx1gg6Kv2uF85EQr8cmQ==
X-Received: by 2002:a05:651c:169c:: with SMTP id bd28mr5164170ljb.186.1639493018302;
        Tue, 14 Dec 2021 06:43:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls3100186ljr.0.gmail; Tue, 14
 Dec 2021 06:43:37 -0800 (PST)
X-Received: by 2002:a2e:864d:: with SMTP id i13mr5184672ljj.58.1639493017223;
        Tue, 14 Dec 2021 06:43:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639493017; cv=none;
        d=google.com; s=arc-20160816;
        b=DsZNPUR+eojngI6o8vOPuddUDbqOzqPsWY4vlG5HTMb21ajfC6WvJ0BBClWEbqdt2E
         dmxlzVaftTvuQvp9WtIsrcAEiTU8ymCTv+Rp27Fr1TuCi7hlMOleygyhewbkIfEB8VkA
         HS2em3wsvSG3IfzbqcDrYwoGdPwRwaDMVpCVTG9CR8YjxtCPg1BvRZ6oob2bq5jQactA
         EZUoDnl5Eb87jwM8tMiZ5NuNX48Nk7yX7cF9LQeUnBGyYZ7XFpsKAG7aalEb0CelS7aS
         a3rpgLl93a+wsxiG38rPssMCgkoBxWdBxyQCrn+wz9NNu1rMsG4u3h7vyorJu/zYG8D6
         nupw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=ZZrdz8Rcb4mC0T+W0Se7DGbnZYarK1D3VtykBkZsxzg=;
        b=Y2yhLsrN4u+5EAKVHJ4CbrVCccXFbQ5MUpMSzDxQzy0MRshfMCxEBnTK5gXtIf7xep
         GPf+oTPJLsq+FbhzbxmJbKdZEwgVpvziMTmvx/jIjRT8wtIdNTS21KY1evAdN2wDT4sq
         PQ6xeHWxstQUYjg8yKAkLExmmQnAn+9KM9oJynaDxixydjJrXDMP2x7r0NkyjTiwHxSf
         uybfl4BT19hnWpJfsBWB6ctq+dCweWmHueKF5FZ0y2C8FK2VU2L27gI+4xPK+GRvuKXV
         z/LFBYMeJbLPjRLOsMQLaIZtXFwxsRmIaHxKSjpi25y72yy36xQZBm98YWFZ6V/sPSDN
         0mdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EA5SlD72;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id d8si786001lfv.13.2021.12.14.06.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 06:43:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8A8DD1F37C;
	Tue, 14 Dec 2021 14:43:36 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id CCFBB13DF1;
	Tue, 14 Dec 2021 14:43:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id TiQ7MZetuGFKTwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Dec 2021 14:43:35 +0000
Message-ID: <87584294-b1bc-aabe-d86a-1a8b93a7f4d4@suse.cz>
Date: Tue, 14 Dec 2021 15:43:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andy Lutomirski <luto@kernel.org>,
 Borislav Petkov <bp@alien8.de>, cgroups@vger.kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Woodhouse <dwmw2@infradead.org>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Julia Lawall <julia.lawall@inria.fr>,
 kasan-dev@googlegroups.com, Lu Baolu <baolu.lu@linux.intel.com>,
 Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>,
 Michal Hocko <mhocko@kernel.org>, Minchan Kim <minchan@kernel.org>,
 Nitin Gupta <ngupta@vflare.org>, Peter Zijlstra <peterz@infradead.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
 Thomas Gleixner <tglx@linutronix.de>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, Will Deacon <will@kernel.org>,
 x86@kernel.org
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <20211214143822.GA1063445@odroid>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211214143822.GA1063445@odroid>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EA5SlD72;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/14/21 15:38, Hyeonggon Yoo wrote:
> On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
>> On 12/1/21 19:14, Vlastimil Babka wrote:
>> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>> > this cover letter.
>> > 
>> > Series also available in git, based on 5.16-rc3:
>> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
>> 
>> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
>> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
>> 
> 
> Hello Vlastimil, Thank you for nice work.
> I'm going to review and test new version soon in free time.

Thanks!

> Btw, I gave you some review and test tags and seems to be missing in new
> series. Did I do review/test process wrongly? It's first time to review
> patches so please let me know if I did it wrongly.

You did right, sorry! I didn't include them as those were for patches that I
was additionally changing after your review/test and the decision what is
substantial change enough to need a new test/review is often fuzzy. So if
you can recheck the new versions it would be great and then I will pick that
up, thanks!

> --
> Thank you.
> Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87584294-b1bc-aabe-d86a-1a8b93a7f4d4%40suse.cz.
