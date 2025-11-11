Return-Path: <kasan-dev+bncBDBK55H2UQKRBEM7ZTEAMGQEBO4BAKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 283F2C4D026
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 11:27:31 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-640ed3ad89bsf6070085a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 02:27:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762856850; cv=pass;
        d=google.com; s=arc-20240605;
        b=VZCK6zmrMUO7H6aVeyF50hVQhHsKInf7roOM+NtsGUnsEAfNwXTgvGbEKV2EHdkFQa
         AXvxdjxGn2hnqngCDBcu/tWOIcke00nZxWlpPsRJFH4gUekJzLGPVOGWILSMEUKvZaH9
         KLc4uKny9WdSfifqFGo0wr5wb2GdfELXtW7tjJg/rUBMc9MaqP6uRDs8Z0OjEOboIFX8
         iMtPv5j2qjanIrdGkFH/KX7YFE8uAvmZcKhClZ92eV1358HH4Dys8FzDB1fWY+z5PInn
         ckXyr057McShAZAi9yr24lVBfaisq+/TC+kSFFWrtKiQHxg53hRmqH7Xvf3kys7aJgDb
         hGvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LdVCV7qmgLxsz+gQDrEXApbgKDOAUwX4NxOWLkKT1kM=;
        fh=Ps6wGDpQmBpoTPGarP8KXdr8dgmIZZ3hGBIE3P5hpAE=;
        b=QPf2H/h8qKNSUJXbnocy4NXyLLn7k6OQ5Orxs3bBGbEhMDfUt7o0K0WhnpgSnzTQQJ
         uenuqMBZUF7kB1DsE0Jep99LxG9VHi+ZhZSiQ7n5m2JDhB2GFxwN2rDSLzoOXbBihCgi
         4wr7NyH0lat9Vu47LotuPSH7frmJH4BXaP2iwT3bWtW907UgNRBjh9XKsj+S1697mqgh
         4Z7P5QgyPXElnh7wPt3kND1JJTKv8fkDNKIauqDn9srBNF5n7p56dl1zQTDYw/WAn4/u
         FuHI+QPPhIDU1AmgK/+VKV7RhAuzHmlzHi23gkk6l2eWggwlXAw+oYemC+tI89lnwXRt
         NJsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=sjb5S7mK;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762856850; x=1763461650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LdVCV7qmgLxsz+gQDrEXApbgKDOAUwX4NxOWLkKT1kM=;
        b=qHwYfcQskQtrZKxMk3M/KzNGPbw5a4p7oUzrvQPJdLSVTuVgf+Af6OHyB/9pTASgeJ
         8Xx5iPlTDRSE5dB4jCXGIQxbYn13cz3MHIcAu84Wg5v1aygaAy3TVTAnQh45Juot9g6+
         00t/ca/RvUWxEtqJK11MH3wx2/z52cdmeD9HpUALHkRG++4W25vpW5DWAImv5I8hPMvf
         lVtx2wQLU6HvClI0LbCKD26HGn2EcoCNxr1RN9P3YjGHwpZ0hoCav6/5yc8WKcfCu0/b
         fFoCFSsBXE85yvV6U+STKaebE5Wv7mdooYt99AnehezVSk9dQJacErPKkGnnvLAKX8w/
         5Hag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762856850; x=1763461650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LdVCV7qmgLxsz+gQDrEXApbgKDOAUwX4NxOWLkKT1kM=;
        b=ncfDH8VWV6yh4kDImwnYMCDHaZunx+juvBUbr0oz/Bpmc9LA125ZK9weejl5jtCZ6d
         WbBPioy417iCrqZcSzxa+wi/jdxrw+iRuJX+bisMEDzgbNlbzuDF9tU4YXtm34Rxo71Y
         dTd3vpVYv0qidilCRstlTSVZEx/rokfKbvlp89Cs7HzKPeu+MONvmPOxM49aEs7U7YbS
         Cxbzmkz9XuSZX3nsW7RhLXzHA4djnN4/VZDPUFEuu5/f3Y5YBpO1Khgb8OT0BFGHc/6W
         HLC5WV+ex0Is7PXA63rYV1oMrOUrcgV6TuaaUBXUK2J8EfQuwnPevoGBBvDmDxs+PHf8
         4pqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBbemrlg50S1pmosZLLYbDw+jI+8fbO0laH6zl/GFYsDsrKGBEM2LLZOeD07IiRCVooJWNiA==@lfdr.de
X-Gm-Message-State: AOJu0YyfAQDutM+Lbfy2er0FySZrydUNObDm3YUfZgbSY5lRdFkw1afS
	K9J10ss+s6f9zcSqWPLZB1wUBkSabZWUOYuOYV5UaCXsqgauJx4XDiey
X-Google-Smtp-Source: AGHT+IEUdeQloBbuXTF2wfiqrXFUG8XVsjz+pZkwZrr5MKbo868YXp14yziYF7biYtiCcXYP6w/9/A==
X-Received: by 2002:a05:6402:1d4f:b0:640:ca0a:dc1c with SMTP id 4fb4d7f45d1cf-6415dbfbb3emr9438646a12.7.1762856850080;
        Tue, 11 Nov 2025 02:27:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y8V2luH41Wt7EUUdToqaQDqeIoX2sx5pRcplRHQBYTaQ=="
Received: by 2002:a50:f603:0:b0:641:5a07:215b with SMTP id 4fb4d7f45d1cf-6415a072426ls3443504a12.2.-pod-prod-06-eu;
 Tue, 11 Nov 2025 02:27:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX3f//kvhChMrPvVh40+TwDlF2oQ53l/GN73nla1ATk1Q2hv+wKisrYU8gey1bGIHNP59v5zgvmPm0=@googlegroups.com
X-Received: by 2002:a17:907:5c5:b0:b71:1164:6a8b with SMTP id a640c23a62f3a-b72e02d3c1bmr902423466b.7.1762856846897;
        Tue, 11 Nov 2025 02:27:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762856846; cv=none;
        d=google.com; s=arc-20240605;
        b=O2CR+cJKe6g/UAhp7CQcWWYjNJJKKbwCaVjcOjJiLmsXbOmkm2FSHV8hg5cuiAskdX
         l8tYOdXGQTZfxxQBoXqNwX20iZ9GKnyIT1FK7f71+/NY9F9mjXdy0/vH25TK7IKG6PWI
         Ve3jkZb7haCmgWcSFkx5NNX0torqP2WC+wkdDKbmIEeE3oHGbM2ItnBo1Jv9r2TWhXbe
         aa4pvEDy0wyIEUohjepk2Cb8/0zd5NwjpHBpnDqqIkWTdoV4b2xBE5ymDEeCe91LiWhR
         Crp+QvdQ7Zm2dgaJUwih6CEs/p4cbzWWUr7rhpEEbDwdr27XPg+kqmbxmRlV+GwY0yo3
         jKOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iCozD/S14h9YyVEvZtzrw1OeE8+mwrBwtubAIDfZfYw=;
        fh=CNgI9Uty9wjUOfcmKxFkFBSGCpOFHexYXIcEAbVFFk8=;
        b=FPVBgDaqpWueO+i9wdiLy7h/fqQXxWCmZ26ygs9aNrg2qiLkf2wommmXgYIB6lkiGX
         b2aOW1KjOB5Rm0egy6XPBXSpXFaKFm51ihEilFbDeoypxI5tIEKnjfyQJ5hT+Ekusvd3
         0842BC9H639/vsmRx1J3uUkkRj86pZV9bbp/k7pcfnf1rJ04BivAm+YdgI+wJwMfvzqd
         RoK7v/EgahBaqMowqDL2VHWz/IkAu5rd862cHioMMOkDw6ySecvjT/qc2ccZLy9wazYm
         Y/06vdue8U7PnfP+2huYNaiWPwTxGMg4bOo9pdgbB719is0b6g128TcbkZyJHJAoJkEl
         cFLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=sjb5S7mK;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b72bc08d36bsi21519666b.0.2025.11.11.02.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Nov 2025 02:27:26 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vIlaq-00000003ivE-1kUw;
	Tue, 11 Nov 2025 10:27:20 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 455A4300328; Tue, 11 Nov 2025 11:27:19 +0100 (CET)
Date: Tue, 11 Nov 2025 11:27:19 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, kaleshsingh@google.com, kbingham@kernel.org,
	akpm@linux-foundation.org, nathan@kernel.org,
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de,
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com,
	kees@kernel.org, baohua@kernel.org, vbabka@suse.cz,
	justinstitt@google.com, wangkefeng.wang@huawei.com,
	leitao@debian.org, jan.kiszka@siemens.com,
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com,
	ubizjak@gmail.com, ada.coupriediaz@arm.com,
	nick.desaulniers+lkml@gmail.com, ojeda@kernel.org,
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com,
	glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com,
	jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com,
	dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com,
	yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com,
	samuel.holland@sifive.com, vincenzo.frascino@arm.com,
	bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com,
	kas@kernel.org, tglx@linutronix.de, mingo@redhat.com,
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com,
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org,
	rppt@kernel.org, will@kernel.org, luto@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, x86@kernel.org,
	linux-kbuild@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 15/18] x86/kasan: Handle UD1 for inline KASAN reports
Message-ID: <20251111102719.GH278048@noisy.programming.kicks-ass.net>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
 <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=sjb5S7mK;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Wed, Oct 29, 2025 at 08:09:51PM +0000, Maciej Wieczor-Retman wrote:
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> 
> Inline KASAN on x86 should do tag mismatch reports by passing the
> metadata through the UD1 instruction and the faulty address through RDI,
> a scheme that's already used by UBSan and is easy to extend.
> 
> The current LLVM way of passing KASAN software tag mode metadata is done
> using the INT3 instruction. However that should be changed because it
> doesn't align to how the kernel already handles UD1 for similar use
> cases. Since inline software tag-based KASAN doesn't work on x86 due to
> missing compiler support it can be fixed and the INT3 can be changed to
> UD1 at the same time.
> 
> Add a kasan component to the #UD decoding and handling functions.
> 
> Make part of that hook - which decides whether to die or recover from a
> tag mismatch - arch independent to avoid duplicating a long comment on
> both x86 and arm64 architectures.
> 

> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 396071832d02..375651d9b114 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -6,6 +6,24 @@
>  #include <linux/kasan-tags.h>
>  #include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
> +/*
> + * LLVM ABI for reporting tag mismatches in inline KASAN mode.
> + * On x86 the UD1 instruction is used to carry metadata in the ECX register
> + * to the KASAN report. ECX is used to differentiate KASAN from UBSan when
> + * decoding the UD1 instruction.
> + *
> + * SIZE refers to how many bytes the faulty memory access
> + * requested.
> + * WRITE bit, when set, indicates the access was a write, otherwise
> + * it was a read.
> + * RECOVER bit, when set, should allow the kernel to carry on after
> + * a tag mismatch. Otherwise die() is called.
> + */
> +#define KASAN_ECX_RECOVER	0x20
> +#define KASAN_ECX_WRITE		0x10
> +#define KASAN_ECX_SIZE_MASK	0x0f
> +#define KASAN_ECX_SIZE(ecx)	(1 << ((ecx) & KASAN_ECX_SIZE_MASK))
>  #define KASAN_SHADOW_SCALE_SHIFT 3

> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 6b22611e69cc..40fefd306c76 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -179,6 +179,9 @@ __always_inline int decode_bug(unsigned long addr, s32 *imm, int *len)
>  	if (X86_MODRM_REG(v) == 0)	/* EAX */
>  		return BUG_UD1_UBSAN;
>  
> +	if (X86_MODRM_REG(v) == 1)	/* ECX */
> +		return BUG_UD1_KASAN;
> +
>  	return BUG_UD1;
>  }
>  
> @@ -357,6 +360,11 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>  		}
>  		break;
>  
> +	case BUG_UD1_KASAN:
> +		kasan_inline_handler(regs);
> +		handled = true;
> +		break;
> +
>  	default:
>  		break;
>  	}

> +void kasan_inline_handler(struct pt_regs *regs)
> +{
> +	int metadata = regs->cx;
> +	u64 addr = regs->di;
> +	u64 pc = regs->ip;
> +	bool recover = metadata & KASAN_ECX_RECOVER;
> +	bool write = metadata & KASAN_ECX_WRITE;
> +	size_t size = KASAN_ECX_SIZE(metadata);
> +
> +	if (user_mode(regs))
> +		return;
> +
> +	if (!kasan_report((void *)addr, size, write, pc))
> +		return;
> +
> +	kasan_die_unless_recover(recover, "Oops - KASAN", regs, metadata, die);
> +}

I'm confused. Going by the ARM64 code, the meta-data is constant per
site -- it is encoded in the break immediate.

And I suggested you do the same on x86 by using the single byte
displacement instruction encoding.

	ud1	0xFF(%ecx), %ecx

Also, we don't have to use a fixed register for the address, you can do:

	ud1	0xFF(%ecx), %reg

and have %reg tell us what register the address is in.

Then you can recover the meta-data from the displacement immediate and
the address from whatever register is denoted.

This avoids the 'callsite' from having to clobber cx and move the address
into di.

What you have here will work, and I don't suppose we care about code
density with KASAN much, but it could've been so much better :/


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251111102719.GH278048%40noisy.programming.kicks-ass.net.
