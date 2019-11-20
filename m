Return-Path: <kasan-dev+bncBD7LZ45K3ECBBMHZ2TXAKGQECSYZV5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D5255103AD2
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 14:16:32 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id o140sf7279960lff.18
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:16:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574255792; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSNwBDJBLb3pvfYhlkQtqCF8bmMoN7yEVbYOHcLdzhxfgmbxLqCooGaK2sd+V9JPD9
         AGuqXqyzwV22rdzflyhqzV0gAh+5Hph6JscaxZQBK0FGCYlI0jZUrHtwTbCnfcDpY+UC
         O1AClZnUuiVCe4iO+M36GfNk7rsW6WXIZE/klVQJsm2kVQZ39o2sdlKxDLsBeFioAXi9
         g4BHGTMSmT4mQg44KyPfMF4HceE39oZZ4evhhAQA5QOmXkZFioiaYMCcdnvqgrA+UD0U
         J94Gc9q9CSMdxclrw/tyz63vYqU1KmeRLkM+PmQaXkk8SJCJS4DTa+cCczCyPJTAJqS7
         AgNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ogOuauL003gkAD8Ukl+O2pkDLmH4cJoxWQMSSV4rPb8=;
        b=k14raE6jdbjFNdCLAdfjHOFVOtvTVFiBOab57hp0JrZaViPyEADlIoGaTeoYmgSG9/
         WlPn5QyuJdiVSP9eFd1NSuUflkt7zLFFZkFjTXvAtqBrxWRW6ZKeVT1yua/Y1BQlLeSZ
         8CchitYZAnRsCPP0EXucXn29SNaB63vfrpSyy4O7M0m1FGPZ2MgN+mIwyFDB4CWTZhvt
         Svgbd3ADFJh7zGON1SjG2YFrzogOCZe+T5K7poHkRkvjHX+OfhFUHmPwKKElEML9O71x
         KS10DVMefigloSU4NQRBV/e1eIXJjlbRiSPzQLBBcaqWdYzW2nDCB7pwYm1NVrw+RvOE
         0dgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vAJwumFF;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ogOuauL003gkAD8Ukl+O2pkDLmH4cJoxWQMSSV4rPb8=;
        b=TxaxwtbZ/0Qi9yJnjlyBJSmXVnvOXoD9CDLynAk4ImW3qdtDz9eHQCoZq5bSc9Zl4Z
         ICSfET6Jhifa+kWcIO750601yqR8oPZF3KsTcPRXSzWvyl/+4APZw3b6yKcTmtahlmd3
         kAgBWUaX3Tq944vfdR/fcyCD8n6zN3tvN9B9Tzsj3kFzzE3v8YQz2S/gUyw9whORfMNJ
         xAdGhUlNec1DXVSGZB0SPex3hIHvSsvY6pJLn4S0A5qM6/f86Qx/5Fpos/ezf3oDcnQi
         3B+Pb4TMjO6s8dy3C/va9JhRxmHyLBlsxKvGOeLmHN5NKrt8gBjntZrOFgljOxRP4Htr
         1pRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ogOuauL003gkAD8Ukl+O2pkDLmH4cJoxWQMSSV4rPb8=;
        b=J3Y+1nTkziM2brSxhOQA1u9vPrBeUbs90U3Bq80vvUVrGc13/C+Vq8ih5vIBn5SyND
         zJO3DOzloJgDkgvNxWLoOXaOqDnXZjRqBUubAB/Qr3hDKSEvBJNbrGoUHb/4Vfek3Y3j
         CRUSMuAZGQ+24jmUQl+P6GYqbDgNt6/uyCvaappzd1QTXHG5skf5E9aTZ1qOVL+4nv3J
         qvTNbr83vc0GMWDcsdp9QA+NuGPoOpw5tYGeTV8BeG/+hVmVQrgEPnxcf37S1aSiFQUs
         7WvH2y4ehEtGia9sMBHHrD1CM9XprIndqWU23wv6UvwCDUd0tHzI2med43tKLyG0j2yj
         vQ6A==
X-Gm-Message-State: APjAAAUQ06N12Y7kqEDYrmpN8GqZUeIOD16RWVm0Jhqy5DuYbzVOOhUs
	7EokgYunjJNxWwDtYG8eO8g=
X-Google-Smtp-Source: APXvYqwFU8Rjo1aSI46SE1qtbOPnuzHDHOwvz2D+q8V0wVowzeXcFikm1xdrPb+UWwXHvbzLHDYNMQ==
X-Received: by 2002:a05:6512:146:: with SMTP id m6mr2779766lfo.98.1574255792456;
        Wed, 20 Nov 2019 05:16:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ada:: with SMTP id p26ls298822ljj.1.gmail; Wed, 20 Nov
 2019 05:16:31 -0800 (PST)
X-Received: by 2002:a2e:2a43:: with SMTP id q64mr2798338ljq.242.1574255791473;
        Wed, 20 Nov 2019 05:16:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574255791; cv=none;
        d=google.com; s=arc-20160816;
        b=efXOfm6sLGRDbpjlCcHhDt2tDZabLxNsuUwkZeSN+R/lxNUFLaRvEd8iT43U9s115T
         vXd+AYHIfKZWkRmJzKPtybK0+XRAR+xgd7FLaJp+Ng2zPAfW9+CX1bf98Ff/URAwetw4
         V1Llr0ocF4wv9afTT8/SLc6kTIw0oZhhjw17z4mCfO25miXOEA4tx4RoCK/B83RrZcX5
         L5B+Lfbz0ZyiXcuPy8KDyI4p1ajYE+Xj5Pt7rZmlm05GUL5p0n6wHmyqOXBQp4SDaHnR
         e+py2dv3uOPf6WOJgSC/v8jGi+oswMIPjGBxv39liHmduwDd7UO1q4bJNayTjFNvHOR0
         8AeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4yrIyYWfXcBOT1nDN68nB0OKsMqoxxmq3jHpYqJV4Eg=;
        b=YoSMHHX41UzywP/Pv16hZx0fGhEPXjyzEZ6VR8SXvDETO6fyKPB0/2ltP02DvuA3j6
         NFmndhV5VQskXNgX5J5SZ0i/sT7dcEt4fwU2k7ctps9vOwciOqm2eXI9WnZYt5ptmlOb
         cNdY25QdKbHiibptwQPScdLKcZgyvew8iC9b0Y/MXfkP6zak6c0lWUuCtIHCtaxOimLn
         ZhAmXyQcSt/G9Eke/sBxj9byyhOWJvOUuVxzHOnORqPcjOxp0Xkd+4SBviyZJ7xx0+SM
         sRyA6FWz59etQGcd88stE6CxGbCV6prfiz+1o0De1EO9V/9AaHQi/ACDALPYJlvepaWZ
         cOyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vAJwumFF;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id b13si1332412ljk.4.2019.11.20.05.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 05:16:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id z10so28093523wrs.12
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 05:16:31 -0800 (PST)
X-Received: by 2002:adf:f5cf:: with SMTP id k15mr3472304wrp.265.1574255790960;
        Wed, 20 Nov 2019 05:16:30 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id a11sm6912156wmh.40.2019.11.20.05.16.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 05:16:29 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 14:16:27 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Jann Horn <jannh@google.com>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120131627.GA54414@gmail.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <20191120112408.GC2634@zn.tnic>
 <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vAJwumFF;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Jann Horn <jannh@google.com> wrote:

> On Wed, Nov 20, 2019 at 12:24 PM Borislav Petkov <bp@alien8.de> wrote:
> > On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> > > How was this maximum string length of '90' derived? In what way will
> > > that have to change if someone changes the message?
> >
> > That was me counting the string length in a dirty patch in a previous
> > thread. We probably should say why we decided for a certain length and
> > maybe have a define for it.
> 
> Do you think something like this would be better?
> 
> char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;

I'd much prefer this for, because it's a big honking warning for people 
to not just assume things but double check the limits.

I.e. this mild obfuscation of the array size *helps* code quality in the 
long run :-)

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120131627.GA54414%40gmail.com.
