Return-Path: <kasan-dev+bncBDBK55H2UQKRBSW2ZCNQMGQE5AAHL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AA59627D2F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 12:58:03 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id j2-20020a05600c1c0200b003cf7397fc9bsf6661431wms.5
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 03:58:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668427083; cv=pass;
        d=google.com; s=arc-20160816;
        b=VYFVJoOXI/TQY6kvwa53S+ZQtC6VmEHoYsb5H07NrGd9Z15LFjCA6FqDnVeROvMawA
         ZvyTB6q7Y+cwwOkCRB/G3E8FI98e7sZe1jsaWW8ruxJ7TR1QJ9vyPbwR28EMcaGRkrjc
         ZvrhYBHNnzjIwb1qDS77cG3noxwoLs8C9SKxSrUq86VXUtTIKwiSYxqi3P1bBcPstNsI
         ZOK33HbccdUKNbCaNQ0TGfQDI2ZQQ+FjdwLtLCbeOrtZIjFXbZi9Cd8YIBtkBEDcSwc6
         pwqG6U42ZMJekBHj7OY7GjFG/gDRERrf4e0qyCsCN/kRMeivklIjKzvfKZ769R28Pg2C
         Vicw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iX5F6XQLAweuQSD3T4ApeOKQXtmc2n+3yJzL1t/uPOs=;
        b=HfxkiDbHHHX2PQ/a2PpAIjsA4wGV/FQJUZHEf6wMKQbHFWvmiuFEmiwKE/6lOjb1Gz
         zbf92T16SBZNOo+F9RDXSAO7WcGc9gy5eY+wySHUnu9dASr1qggaPtiu+8oFi6hza8qo
         2YwaxbDcd+0A2vp/WH+PBy6g7pOx+uuMOxcWyGdu8ONm7MBiayj4TlKeBXvp3jSF/m8e
         QTQSBR7OPxBs8b8Rw1Vr216sVPcXCwnWJ1SIRHsmG3mmAHPGFGQdgM13mhld1jeW7lP5
         yc4DHGIgjWQwTFD9+54+DBA77oLV+yrZWT2EmufG3RqTaGe1MwUxj4qovVBKf23utsb+
         AELQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=V1U0mMHU;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iX5F6XQLAweuQSD3T4ApeOKQXtmc2n+3yJzL1t/uPOs=;
        b=WcUVtS0RU5Nuy5ZXh9rKQ+EIvdZT2aDo0rbR/hIEwUgDFetZxMIJ+LwJ1+gpu3X9zz
         Dw0mMfpLHfyreYxScX3SUEjhXRA6DjdKiONbZByF1qoTRAsu/J0uPmd07LiqSjI8pKec
         hLO0K7cJVWsT3fmAdw03Jsl+G9QUNWoHxCSbzK0Ie+uTE6zSvMml8hsP8BcOzCb2GGGz
         2SD+tDUkSXDkjGq15UmeTCM5Lw2O1jyZ3cHuj16eqV+09yZR0DZUJKBxf/KpGHs+hveU
         uOARz8RJ4927jlXeX9sFSfhTmk8Jn7KL9Ho7rOsJojSKA7llRKzV59oSd0Rey5NTD6cR
         me9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iX5F6XQLAweuQSD3T4ApeOKQXtmc2n+3yJzL1t/uPOs=;
        b=1657XM3X1ChI02lgIHjcRq56fqRHf/R1SgOswOd0ghUFjDpt19WjVYjXQE+/u6hP3K
         K6wYY/G5TBq8Y4Nf223N+2NaHYayWEzNGHiBpsqou1bkJ5GfeM+hGaDYdC2hcHHk14rY
         ojTVs9bIogFrQWVNR7hWIw+uENJgOu19NNcLaXJFRTJl7W67WTI7fb5Vp1oU2AaLrMfZ
         H84Z/IjpcBLT2uN4FaCLzgO4tKeOmq8ZcoFesREhLZC+dTNMMBRLsYnl64ddPpnpcCqL
         0kextVVGqr6pxGH4Z8YofYnePEuYEnh8RpJ36vUnZd3tCoUjZx982HKZCjoiWK6R0JEF
         3QYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmMDasgTlcuX57tm3krgtwhIomJ2s971unpwwIRz7astnAabBQg
	QK9nyJyDtj58QOf5PihqE7Q=
X-Google-Smtp-Source: AA0mqf4XBOZlGiV8taSYXH03TISb7K++HoyhTcsVqGvg6OkmgfPNhHWTrG0Ocq5ZNTGK/xi1G3pTtw==
X-Received: by 2002:a5d:458c:0:b0:236:7005:7e4f with SMTP id p12-20020a5d458c000000b0023670057e4fmr7744624wrq.337.1668427082897;
        Mon, 14 Nov 2022 03:58:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3cd:d7d0:14b6 with SMTP id q22-20020a7bce96000000b003cdd7d014b6ls5426975wmj.1.-pod-control-gmail;
 Mon, 14 Nov 2022 03:58:01 -0800 (PST)
X-Received: by 2002:a1c:ed16:0:b0:3cf:a616:ccc0 with SMTP id l22-20020a1ced16000000b003cfa616ccc0mr7824947wmh.73.1668427081678;
        Mon, 14 Nov 2022 03:58:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668427081; cv=none;
        d=google.com; s=arc-20160816;
        b=eknk3wJxF6e3I/RmcWqSUhC+hH7E83Jt/hwHgY9CCQQrmr3/DSDE06uEWty2x/A6O5
         Myy3TpeaMDJkk2WKkm636xykziqkdUA4QGj8jN/gk679V0quHEd7c6JZpHwN16LVsoGo
         vPA+zVtTMiJCmAfpgY+VnLW4t296yUGde3LjF7bAL0PlN8Eb63U79je4FNnzweeGyc73
         WLk6WoKkuYQekUSpqhC1XuOIQDaEUtuiQ6N1on9LhkrtgsOC07HbBmzHcN1pkdJGUc0/
         UBbrg6KUIZkYeHZVkTEEpLr9eqTUETbc3GL8BfJ6Fj2dLTHd5fxuw7SXJY4lckSrhwz7
         npjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=40sIaQoouB2fCw1UV23MMK398vTaLFekQy3cMh9yWEc=;
        b=Tcb7TioCNfmbHtFmiH+AWn7+rKU7vEoeRXODGlhGhKxkhDC8UAtoqzDznpk/dmYEY1
         bQLMCDP8tTQax7oW16Aax/lidzVh0jcDWsvL8ZMg+dPMw6gtGRBiLwmm0YjiAJxbJfxL
         BkMtjq79MkGunEn4b8Lf+mPKdkrAz/kzKU0bA/Eft2n9TiiVWtt2iEqaqdB+PnNu+TjK
         rExFlcyyN09K4ll2/BV4yDyZDDP5CXUnwtneyW2dQaulOPYiYFTgfbmcp1tNPvOc4U1Y
         6QuCOXd9saueVvzhEREYhr1b9wtqhBmnLwLBj45JPcLqiez6VG/nOLH6Tn4E4zcqzWYE
         VbxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=V1U0mMHU;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay5-20020a5d6f05000000b0022e5cd5f848si314463wrb.3.2022.11.14.03.58.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Nov 2022 03:58:01 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ouY67-000p0Y-E8; Mon, 14 Nov 2022 11:57:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 568CF300392;
	Mon, 14 Nov 2022 12:57:54 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3AF792C809EA6; Mon, 14 Nov 2022 12:57:54 +0100 (CET)
Date: Mon, 14 Nov 2022 12:57:54 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Sean Christopherson <seanjc@google.com>
Cc: Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Subject: Re: [PATCH v2 0/5] x86/kasan: Bug fixes for recent CEA changes
Message-ID: <Y3ItQm4Q+zvsT9eD@hirez.programming.kicks-ass.net>
References: <20221110203504.1985010-1-seanjc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=V1U0mMHU;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Nov 10, 2022 at 08:34:59PM +0000, Sean Christopherson wrote:
> Three fixes for the recent changes to how KASAN populates shadows for
> the per-CPU portion of the CPU entry areas.  The v1 versions were posted
> independently as I kept root causing issues after posting individual fixes.
> 
> v2:
>   - Map the entire per-CPU area in one shot. [Andrey]
>   - Use the "early", i.e. read-only, variant to populate the shadow for
>     the shared portion (read-only IDT mapping) of the CEA. [Andrey]
> 
> v1:
>   - https://lore.kernel.org/all/20221104212433.1339826-1-seanjc@google.com
>   - https://lore.kernel.org/all/20221104220053.1702977-1-seanjc@google.com
>   - https://lore.kernel.org/all/20221104183247.834988-1-seanjc@google.com
> 
> Sean Christopherson (5):
>   x86/mm: Recompute physical address for every page of per-CPU CEA
>     mapping
>   x86/mm: Populate KASAN shadow for entire per-CPU range of CPU entry
>     area
>   x86/kasan: Rename local CPU_ENTRY_AREA variables to shorten names
>   x86/kasan: Add helpers to align shadow addresses up and down
>   x86/kasan: Populate shadow for shared chunk of the CPU entry area
> 
>  arch/x86/mm/cpu_entry_area.c | 10 +++-----
>  arch/x86/mm/kasan_init_64.c  | 50 +++++++++++++++++++++++-------------
>  2 files changed, 36 insertions(+), 24 deletions(-)

Thanks for cleaning up that mess!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3ItQm4Q%2BzvsT9eD%40hirez.programming.kicks-ass.net.
