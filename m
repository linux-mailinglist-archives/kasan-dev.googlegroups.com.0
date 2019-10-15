Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4WNSXWQKGQEAUBKV7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id A5AF3D6F91
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 08:28:04 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id t7sf8770185otm.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 23:28:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571120883; cv=pass;
        d=google.com; s=arc-20160816;
        b=rhEmtC7/RPsIL7NyfcMX3c8RyWhRNin6s2PNjc19E6aMVTqy6hrTxywH+jYWTznUWm
         D8EOu2rLKSxCkQTn3mRzmaJ++zCpVCJJqspw49Cn1o9DV7HLlJi+LydTdiSrWyQetu8r
         RxGnj+btRydH/EHM7mcO6MXE74k+nk/JGMCt1BJ00lQzlXATTKj9+S3DrkTxtT8WdZ1l
         reH/itLuIlfSDUUDdfNjveoa+QXf2BelkR090gK+oK47aAmvBvq1cyq0xdBlk0hjHcjq
         15Ng6lA2zFXi1X9hOo3hySP0YhlQDpRQrI9ebfMpqMwPLwKckoP9dj/s4c1BZvsaBed1
         w/Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=B0Ospw65GRxSFMLj3zDwS3a0kpEwJoycc6cLGaLd9xU=;
        b=sX2TKNicVWU4PFnwVh5TendoMcSvBSWm9RA5PMn6TmcZJYxm//3hbSRMqkuAMSIeZQ
         f1NWNqyleTSAfGWjtCzO+U6YDS4FFvBCwO7beaEuoLglrGu0WH9X0tpdI0wszHFVQ5Yq
         TAdzlU4FCepi1/OseLmfgk3zcqc+lqIw+fPas14sco41ummu1qTnccSQ/O/7oRgLrvy0
         l7XgIKeTBbnOZkqmCMUjFRSsNVu31VwKZDg6el3Cl6+WIWeqhbNLlM4GbaGM9hS7hYbZ
         lFYYYbgMej7yBqpySDdM9xDR8GdaGprxS5SojvkAD5Q0fllimCGgJufe9d5BUcGewAlh
         OdEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BrUhn4gp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B0Ospw65GRxSFMLj3zDwS3a0kpEwJoycc6cLGaLd9xU=;
        b=FxqGRlZ1mlEalkbCwDgTLCQhCmraS5UmzXTyNfHa+EnfGABcwk3S4dIKLThcsKqinx
         clN/j8Qh7M4aiUzes7hNcRKjiuZzwUpuf8n0rZ5bMDn4/WQesDDmO8sFMg7NeNKmC+Xm
         YGx+pj8WdePRdWGzwlzCirIJp30yety63BmNvsMrACYOYofa5Lv7Mvy0MDRjaGa3enb5
         EXdUSz5EXvy09bhOCgb83KgivrWTppXPEjOraLSM0pZdy3nCnrgjKJyh50mL2mApIcNb
         g0FIQPZPsZ1An0LOS/KSs346QYNb2VxAiX0BcySkJ2oKl4eI6KNl68kQv4jTf8lEMU0b
         9rMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B0Ospw65GRxSFMLj3zDwS3a0kpEwJoycc6cLGaLd9xU=;
        b=iQO+3HEd7BT4rSDbQrw3JW7CLD6VZeHyESOa7nPpumi7Qu2GD7Q9uSmiWfVHuaSZ7J
         VCe1hDnGTxmGSOD/cHwsR4BEwblTs49VFnYTUbSwQTKJ0ytDgfe5qJ6aXm2cqXeeBeg2
         2B34YD6D+qG35bSWKfwPH7yJrExn4tOitX6EctzVi+YYaM+a3R5uF7tmvhafa+547dYN
         EqxcjGolu7jQjrrQkq89RI2l4R8Ym+/Jbd/mwQ5K7sJZ7TSzpCJe5vEFW9Ww5duHPSWR
         7OhUPo2JyK/LA2bn/kEa7/6pWzjUiGYt9oJTJp+CRMSPoAaCR6mdEGyDn3ExbdLOyBG1
         1fUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX9ZCsLtLKKMyjBxAGelLP24KkSj/mHbN1G/1xLz91Ijy+sGNNG
	sCoxi9q8fKvG04eWYd0OEaA=
X-Google-Smtp-Source: APXvYqxi57Z/ICCoFPCOHBFSMX7NwZOYWSaAzIvBMDCblczKy2U028qT0LmbqruYVjn+3VE7+D7yYA==
X-Received: by 2002:a05:6808:255:: with SMTP id m21mr27889367oie.32.1571120882969;
        Mon, 14 Oct 2019 23:28:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6acc:: with SMTP id m12ls3090227otq.4.gmail; Mon, 14 Oct
 2019 23:28:02 -0700 (PDT)
X-Received: by 2002:a9d:4718:: with SMTP id a24mr12177434otf.345.1571120882637;
        Mon, 14 Oct 2019 23:28:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571120882; cv=none;
        d=google.com; s=arc-20160816;
        b=sVXaNeYka+ply3mZvmH0EqdXSzYeMOggprdZRyRBiINicx8VTQHsnAi7GkE1crYkB6
         RFLrBPH3+VbWu5ThRfWJIPUE/7W4WiBCItjfRKL5W0gfVqX3BGTyvaWFDReGeEzUNSJX
         nD8YBuJozChbkXuR0afm6fkGInz9wLBoIbZ+LsCYFFxgSEFKTOUjirTbBv+Nxs0GG4gf
         U5st4THln5l09qw8fyfFTeKiWrFFGNNd/MbNu5818XGLWq43QpNPZ+m8s0MaeOLxo3Vf
         Z9yTJw292HepZMXBNCP2kZEAH1nrKb/hRDQlrenCKJSOnMlSe9qVdTOIMIot1kqAGfth
         PAQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=NXE3NjexAQXsjlqVk+3nF0FjJ7hypONs1Weo4aM4img=;
        b=dtyM2RkKhkgVdx2dQOxZGvIo4yxIrjjmL6DkHeJ119GCq3Frfc25ZaAHs+yuqiRBN5
         JUtWTQtmFBx4Kj4u71ziNYm0dQhCE937Fn7Q0iMZEpBzAKiM5smK2LqCEpD63x5XjBco
         f7NUWUeiNz0xAq7bAEN32sDZod84D1jxlDHjsfo5zGLX8PAxpl/LPEv8ERENpLVsrRE8
         EeTKEmTOZPBz3XxNTpFJpd6gSlSLa6Om988pspAkMWtv6O8xmf0VIuGeT6ZGkH4t7/Iu
         P96+OSgrxF/b9FM2hNtWHRdaBiHUHDJYQXPgqT1zMEPUCYcD0ME21GPyyKjCwuNulQAr
         qqxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BrUhn4gp;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id w205si493862oib.2.2019.10.14.23.28.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 23:28:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x127so11782487pfb.7
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 23:28:02 -0700 (PDT)
X-Received: by 2002:a17:90a:6302:: with SMTP id e2mr39528114pjj.20.1571120881762;
        Mon, 14 Oct 2019 23:28:01 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id q76sm44206995pfc.86.2019.10.14.23.28.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 23:28:00 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191014154359.GC20438@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <20191014154359.GC20438@lakrids.cambridge.arm.com>
Date: Tue, 15 Oct 2019 17:27:57 +1100
Message-ID: <87a7a2ttea.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=BrUhn4gp;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Mark Rutland <mark.rutland@arm.com> writes:

> On Tue, Oct 01, 2019 at 04:58:30PM +1000, Daniel Axtens wrote:
>> Hook into vmalloc and vmap, and dynamically allocate real shadow
>> memory to back the mappings.
>> 
>> Most mappings in vmalloc space are small, requiring less than a full
>> page of shadow space. Allocating a full shadow page per mapping would
>> therefore be wasteful. Furthermore, to ensure that different mappings
>> use different shadow pages, mappings would have to be aligned to
>> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
>> 
>> Instead, share backing space across multiple mappings. Allocate a
>> backing page when a mapping in vmalloc space uses a particular page of
>> the shadow region. This page can be shared by other vmalloc mappings
>> later on.
>> 
>> We hook in to the vmap infrastructure to lazily clean up unused shadow
>> memory.
>> 
>> To avoid the difficulties around swapping mappings around, this code
>> expects that the part of the shadow region that covers the vmalloc
>> space will not be covered by the early shadow page, but will be left
>> unmapped. This will require changes in arch-specific code.
>> 
>> This allows KASAN with VMAP_STACK, and may be helpful for architectures
>> that do not have a separate module space (e.g. powerpc64, which I am
>> currently working on). It also allows relaxing the module alignment
>> back to PAGE_SIZE.
>> 
>> Link: https://bugzilla.kernel.org/show_bug.cgi?id=202009
>> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> [Mark: rework shadow allocation]
>> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
>
> Sorry to point this out so late, but your S-o-B should come last in the
> chain per Documentation/process/submitting-patches.rst. Judging by the
> rest of that, I think you want something like:
>
> Co-developed-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Mark Rutland <mark.rutland@arm.com> [shadow rework]
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> ... leaving yourself as the Author in the headers.

no worries, I wasn't really sure how best to arrange them, so thanks for
clarifying!

>
> Sorry to have made that more complicated!
>
> [...]
>
>> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>> +					void *unused)
>> +{
>> +	unsigned long page;
>> +
>> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
>> +
>> +	spin_lock(&init_mm.page_table_lock);
>> +
>> +	if (likely(!pte_none(*ptep))) {
>> +		pte_clear(&init_mm, addr, ptep);
>> +		free_page(page);
>> +	}
>
> There should be TLB maintenance between clearing the PTE and freeing the
> page here.

Fixed for v9.

Regards,
Daniel

>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a7a2ttea.fsf%40dja-thinkpad.axtens.net.
