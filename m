Return-Path: <kasan-dev+bncBCV5TUXXRUIBBMEV6GFAMGQECFNHW3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 79DC8422710
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 14:53:04 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id c8-20020a50d648000000b003daa53c7518sf20240599edj.21
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 05:53:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633438384; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wy0e/59TI3fwzE5r3c42byQULREcft4O0abwVmXA39ETtr+oq2IbTKxWoQyIwittg+
         uAAndN8lyAgZlD/+Jv3VGq9HEQKFs27q4q1KZmlAcpqFAObItDyUei1keiyArhuzGCz5
         fUna3tyAp4IPfJNSpAs5nahtE8Oip8Ca76lFpd6KbIS8yc4Zjw82kz4vDiaByJQnxqEN
         iiz63q4Fhkmt0BXp4GNnu+MqWFH6Bo+Oml3HqrcnQUiRdMfwgE8UtVbe1DvgBFmJLrvp
         EBvMRBj2c86EilGkCIIbHkcuOoZArH5ARn9J0AlZUC3tLFpj75XdgixW+e28TPRnUVhU
         TAqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XqoaF8OuqjU5qLTG2ku9Ww82th/tlB1/pdb/bvrKrI4=;
        b=ZFRFIPLQjQFndknc0z5FuajG6EGE7pwRIjH0VP/HPko7f6Mku4mWeSDGS+oPis+pat
         wg8pI5bJGAeFayNUmZwBWeD0rRBYLcIC5REGwoVD/QeAvRFjM2atEJiS0S73lhA8C4KU
         3BQ+ZVxyC2LuGFmwCA43JkKZGYfbn4eYOwy51K53DZunYW1GPq438uESiwBiODFT44DL
         u0MhNWWV4JqkjWJ7IX5sA9ExgSpTCmxpwp/yI9gHeSWTF4Iu5uVc5Y6qCWPMUuMLthAF
         zgXHXO21bpaCeMf4CbEfhAl66xF5ds40oWLHMkqPhFYKwAzhQhPsVSrS+rIG9ipFK0cf
         AGWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mgxTuiy9;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XqoaF8OuqjU5qLTG2ku9Ww82th/tlB1/pdb/bvrKrI4=;
        b=YgMRN97TVJnbcjNObJrI+ZR8VEa3hPxwxqxYWNfkSdMj7k/KWUVm85KlNTE/9EHAAJ
         ZDj2MvzFiaJqoaz0gk6sgPdsI54NP7KemCktcAWvrCmaj0IffgXkXpXFMawfms4oIAmi
         YbXwbeRKSVaAIcWmxI8umxN3pVut/K/FjPKVUcQW30Y//gl+LKwql4kH2JoHBPdda+KT
         drPHb7GC9DL/6Fv2qh48uJxz8L4cIUoL9P0lwyJQzUIQvWQ3xqJkGt3JDsT5TCLmqDaU
         O/FODBGz0BzJ5Afa8joJnBft0g2bBmoCeGGHd3iW7SLgnf6Ly87Wkq1BPK0n/8Ei0PLW
         B2vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XqoaF8OuqjU5qLTG2ku9Ww82th/tlB1/pdb/bvrKrI4=;
        b=KNzBO2oQ779qMcXCxQnLvg2P2nB3RTU0Dy2MTFpHso+lAAIb+ESvyORLnzO3Xkfa77
         6VK+puO1OH3up3iCOetKfKEGoCo0iR/ql1667JjGELkuGSmALgMul3Ss054SLzYA5CtL
         zsjb5for/wImnXUdEIZfGPYjHXa2/7qCRSNK/euLA4n+bnl+juu7dFrCytEj6pgCp0Ok
         ii4WYcOK62FcfHlIbfPkpiyZVx/HI7oC38HK03FoMqpbSwL1iUsAb6U4cdrQW/0MhEqG
         7osGPbPwsQ9lRlph7ihXnThRMlZ34ucMTcXRokd039ByKjQoBGCKWdW1Eho/YFj7VINk
         Di5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335B0aNLjMwvCuEHmKRA9NVuO+xZOYQmoHvr91r3L/aVaq5SB2G
	AfLOKLIN9Sr+QB5dNOQ6UNg=
X-Google-Smtp-Source: ABdhPJzF4M4Vu3bYEVQbSZkX+iu4lT38T8au3I+dy+GuuY18ih2xkYbkzhf0BmA/ofUg1+r/cA11Zg==
X-Received: by 2002:a05:6402:4384:: with SMTP id o4mr1395025edc.33.1633438384263;
        Tue, 05 Oct 2021 05:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:18c:: with SMTP id r12ls4103777edv.3.gmail; Tue, 05
 Oct 2021 05:53:03 -0700 (PDT)
X-Received: by 2002:a50:da42:: with SMTP id a2mr24994565edk.361.1633438383414;
        Tue, 05 Oct 2021 05:53:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633438383; cv=none;
        d=google.com; s=arc-20160816;
        b=lOiFGubFmPtMVXbdVQNOZaO6xvzswAZo5k32SCXYW4FGFou0Ci5KaPFNsQsAu49SY1
         9D436ZNOZeMHhstSoesST2W5Vbgaf+z+MgM9fGY7LwBnGiEzfiG4T1zq4Z5k5NABwUkj
         Vy4FWAB4XzNq7fvhnYHVVNNsIvVXSaMUGIwXC5hqiNlBRgy/JBYosKBxq+mGAA1QPpa1
         JRNFfFtj2QlBTJCuuDizzfFtendGxJkOJnkmyUTEvtb8oLUQ0fD03uJXYsg/dj3Ye+o9
         E+jkOT6vmeGlTCppSg4GdE+7KBDxDOPDWMTUQb1e1bCostV3El03Meyrjgb7wzE3oT3i
         IhYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3mL4e6pocxVR5OsISP9dNIeRYN7ixRmDV8QCVBso/L0=;
        b=fOY7+Vj5Goj4AltfrCPv/TjnAI3AFGSe2585Lqfwi08e3J8nCe751FzvLkAf4//p55
         1BRDQx4uG8HbhnyiOW3tivqTWkl2mQg4lB1DpX41Lu/2AKusnL4ZQY5LL/9pNYuxZEdl
         86cz6gJKhMMk038H+kyexRFl3ZiVmH2R5HTR95pZGAP+FYM6IzpR49HVxlwqhs9+TBxW
         eFHX5IrgLCz5sJix3SrZjEpYMSPyuOvhntguHtV7cUz/Ig4Nz+SiPtSI8IXNdEx5MpUN
         gF+P09VJvzwE/mTpcTrfVY5GsLHcjbxs7maXrtWbj4wd32J+HGC2LU80nqjChhwt5s2X
         suVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=mgxTuiy9;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id zh8si1194432ejb.0.2021.10.05.05.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 05:53:03 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mXjwF-0083AP-Q5; Tue, 05 Oct 2021 12:52:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 25C0130019C;
	Tue,  5 Oct 2021 14:52:54 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 134AD2026A8AF; Tue,  5 Oct 2021 14:52:54 +0200 (CEST)
Date: Tue, 5 Oct 2021 14:52:54 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E . McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH -rcu/kcsan 04/23] kcsan: Add core support for a subset of
 weak memory modeling
Message-ID: <YVxKplLAMJJUlg/w@hirez.programming.kicks-ass.net>
References: <20211005105905.1994700-1-elver@google.com>
 <20211005105905.1994700-5-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211005105905.1994700-5-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=mgxTuiy9;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 05, 2021 at 12:58:46PM +0200, Marco Elver wrote:
> +#if !defined(CONFIG_ARCH_WANTS_NO_INSTR) || defined(CONFIG_STACK_VALIDATION)
> +/*
> + * Arch does not rely on noinstr, or objtool will remove memory barrier
> + * instrumentation, and no instrumentation of noinstr code is expected.
> + */
> +#define kcsan_noinstr

I think this still wants to be at the very least:

#define kcsan_noinstr noinline notrace

without noinline it is possible LTO (or similarly daft things) will end
up inlining the calls, and since we rely on objtool to NOP out CALLs
this must not happen.

And since you want to mark these functions as uaccess_safe, there must
not be any tracing on, hence notrace.

> +static inline bool within_noinstr(unsigned long ip) { return false; }
> +#else
> +#define kcsan_noinstr noinstr
> +static __always_inline bool within_noinstr(unsigned long ip)
> +{
> +	return (unsigned long)__noinstr_text_start <= ip &&
> +	       ip < (unsigned long)__noinstr_text_end;
> +}
> +#endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVxKplLAMJJUlg/w%40hirez.programming.kicks-ass.net.
