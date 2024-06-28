Return-Path: <kasan-dev+bncBDBK55H2UQKRBRXW7OZQMGQERPI3NII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 70FA891C55F
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 20:04:56 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-36743ab5fb3sf1031133f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 11:04:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719597896; cv=pass;
        d=google.com; s=arc-20160816;
        b=szOxklDLQ3OFUEDnCiObsY++8+8tu9KhFBZtmMNifGmmSjLjgr86zgRncrcs8OVmvJ
         iuoDn4CgJnIxwNRofVp5yDYNccBdt67dwJwNqs9PSViXuh7ftQLbql9qfPRrxmNqZ6zo
         8+7GtQzzGjUIVuXooCGGLVhi4o58Jp3uLAXk27U3frcxBD1Epk1ZVebGuZvEw6cfbwFG
         0prOditrGw8M7XqpOONapYzAbRJdpSnvm2/8w/vTHUUlQ1hP9KvmCUqn56/YtREhCIMQ
         k2ftl3l/vsJUjDAFxekylQmrm4lqdP+DEp0aNNGD19Pj+7d/zPdqAsWGVutDOtKPMaEQ
         ckhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7NRUW1q3lV+lDSSFaysH0QYWVR4cpkhUyPChTI2/rYg=;
        fh=2UzDEblHBgUB4zD7ma73GyFAastOVfxPpmEWMPxxyKQ=;
        b=vdbQMaj+U3dvdGcRbYRIGtH5JUt5cJzB+kQWbC+GlkMipMT3XJkpZLQtIF534jToNO
         y/pTZkkmGdHT6IRvRLnQOnnDEaTjBX0za5JOihu+GQyt8mW+iH3T2EqWpjMp81NPv3oe
         pCLwzRsyU8GWL0GE9RpcY1SEdj9DA9oAUVCOs8xiDi2AC3l37Po3+ueQMAr7ny0uKzOH
         9yEQWI032DgDBcPZkIwE7njqQWl7XfZo8rSp9CLnvqmWAw8x+A7uOz9o3uyk/A2fMa12
         5O1Eg8/996B0CM3UUIYNn3ClXZUtkExhpUvmtecpL2wB0+i5A3IFcsa8CzsEagJoHiLT
         Q84w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=F5de3Ybp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719597896; x=1720202696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7NRUW1q3lV+lDSSFaysH0QYWVR4cpkhUyPChTI2/rYg=;
        b=Sfhjz73wLqBbZLU2eT1NrW0oF3+MApuVqm6OflwBk8hnNpZUC2FtpyNJvIPiuUBcUm
         kRUlyHna6Wrmh2x59Kel7lMQg9wG0WtJudiqNzWrbLNCWrN+C8aODa5RyafHW/dl52EA
         /iwakahYS9+U2wj6sd61Jfk2W0ueGxsV0Ti2Z/5j4ej7mpmFhGKFFfeBYCU2/o09k9fw
         /P90cjtidMYy2mjJA8jgi58AwHWF76pykS6HIkNUIN1nsOjdF9ZaaryvYOlxdwf0k1M5
         haeVN9Wj7zm+xJygXxVVjo5oz62qaqjJOAXbLxtLWK6jW3izgICiFWExrrNeuBt5Cn2F
         DBxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719597896; x=1720202696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7NRUW1q3lV+lDSSFaysH0QYWVR4cpkhUyPChTI2/rYg=;
        b=ZvaN1NE29OaYOD12VVt/5QVYLn21WfUiVtz7CbfjD/DtX/MDbXIVNATalSnHerKPXU
         eNrXTFuV0kh6ki4lzam+C8cNwpPd+4/wQPmuHpdOAdWS+3LYjulN9fA8QVWuajtFd0+m
         p8X69YHMY4Txg2VItL5Zggk6id5w9tR3TuJ2TcdmU5Ep43GrHy+kIH1ZvjH0Q0NWurf+
         vNDF3A6qAwEp7TNUc0PH3drKXjPLFHWSrhbQ77Xr5DxRusi7+g/JPGEk28+t9zeul6Ia
         KczauRUQ9hh1es0ekxERiDV3AF3/6v2yGKjHyUjOhS6VXzKU9d5zkvGjOEovTJ1KCxtP
         er0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcRrZPE/v6i8DOS/m1iZJFrUzQVKR/IVmRLkXfpofsP0vx/Wy9ssPUV9S9aDfowT6ySiALs0ggiRGnMiKemAmYQGI4qL96jg==
X-Gm-Message-State: AOJu0YzveYjPPK5oKJufZwTFC4StVp8WUFtAzBYUksJ9UDeT6pB77In6
	rfLF9Fhpbkx1Ykf1RWq7zVZofccqeIWN1dO1xrL0+impjoWk8rDc
X-Google-Smtp-Source: AGHT+IELRmyHw2sjwapCRJwtrBQBwicq1iUooedvgrDqFYQ9TFk0HoM7ghazpuPj8AjlBIDMUpT9gA==
X-Received: by 2002:a05:6000:400e:b0:362:d0f7:1e2d with SMTP id ffacd0b85a97d-36760aa30dcmr2361935f8f.22.1719597895163;
        Fri, 28 Jun 2024 11:04:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4708:0:b0:35f:1b09:66d9 with SMTP id ffacd0b85a97d-3675a87a139ls453998f8f.0.-pod-prod-00-eu;
 Fri, 28 Jun 2024 11:04:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMvyQMarrJnM7uymfc0duk+hbUfnlgGmYQsA9Wk0lCNEjZgX+UxEj+cf79zgRPWmQtQ4eiaH2ups82YmQ/7KKuN0hi6GXRErYD+w==
X-Received: by 2002:adf:fa82:0:b0:364:4321:271a with SMTP id ffacd0b85a97d-36760aa2ea8mr2240451f8f.25.1719597893138;
        Fri, 28 Jun 2024 11:04:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719597893; cv=none;
        d=google.com; s=arc-20160816;
        b=uLJF7L4KorDByV2yiQsMiJ6AuWYR7kBf8b5d7unie1NPmCPfb559mNgUbtyJQ5gbzz
         K0cXQAOehK0tDWv0nsCTw9VNsO2UM2bQ0ZSmd3fJ0dPlf4ua2dB37u/uopgfmFcJifAW
         3NPfZ6RbiwI4nV6q/rySYhLOgJCfMvFFMZhfI7tLAsbcfEQhJPhxqDrvdAbB748EbFRY
         KWIeB6yku/QskQHFQcANCwMV75LytoTAj0394xPD+SHxlyjErvV1xSEgzChjE1Oicf3j
         WsEXKim/Tb5EkC4lNSOzZGEQ5cUj369P+XAT+9kXj+yCU0sz2LKzeqeUFEznFSvLgcPf
         8tVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dSrkPPHv57iagKOJvURV1RqHc0rOI3RdmSfKvjD0uAk=;
        fh=JmXIGkC9xZXlqcq6n2eZS+1+ePcl8AaCyq59L4ex1Ik=;
        b=xxko3jVUVUzrIw2NVuSzUZnjnuk5QNaEiuMJbK5D/USVjEzBBLqpGZ/kx9rlPXFumb
         ZlK9Qp1z5ST5zPTDDXnRP/7dN20BSFDx37wzR/IFd78O0HysQ8B+S4ecNbpxvgKpG4px
         vweDeMXbQs/sXtVJWe8mlI25LWDbaKPcH/11pf/9yq/OBRq914fUTw9fQeKCBD/R140I
         ZbrhoEWcUMSno++RVH+8ozB4qz89cAXIpDiXjWOP6YWORFBSqkebzdE9Rz3hInngWMZK
         VCDo6y+wgyke5yydkYxhyKNloXsrLl6KNQNArBIOCA+mJSJw6soaray6Apk4K6bghnGG
         eD/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=F5de3Ybp;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-424a2ad799bsi4638805e9.1.2024.06.28.11.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 11:04:53 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sNFxj-000000094Vb-431B;
	Fri, 28 Jun 2024 18:04:44 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 28A44300400; Fri, 28 Jun 2024 20:04:41 +0200 (CEST)
Date: Fri, 28 Jun 2024 20:04:41 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kees Cook <kees@kernel.org>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Uros Bizjak <ubizjak@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v3] x86/traps: Enable UBSAN traps on x86
Message-ID: <20240628180441.GJ31592@noisy.programming.kicks-ass.net>
References: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
 <20240625093719.GW31592@noisy.programming.kicks-ass.net>
 <202406261205.E2435C68@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202406261205.E2435C68@keescook>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=F5de3Ybp;
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

On Wed, Jun 26, 2024 at 12:07:52PM -0700, Kees Cook wrote:
> On Tue, Jun 25, 2024 at 11:37:19AM +0200, Peter Zijlstra wrote:
> > Also, wouldn't it be saner to write this something like:
> > 
> > __always_inline int decode_bug(unsigned long addr, u32 *imm)
> > {
> > 	u8 v;
> > 
> > 	if (addr < TASK_SIZE)
> > 		return BUG_NONE;
> > 
> > 	v = *(u8 *)(addr++);
> > 	if (v == 0x67)
> > 		v = *(u8 *)(addr++);
> > 	if (v != 0x0f)
> > 		return BUG_NONE;
> > 	v = *(u8 *)(addr++);
> > 	if (v == 0x0b)
> > 		return BUG_UD2;
> > 	if (v != 0xb9)
> > 		return BUG_NONE;
> > 

Looks like I lost:

	v = *(u8 *)(addr++);
> > 	if (X86_MODRM_RM(v) == 4)
> > 		addr++; /* consume SiB */
> > 
> > 	*imm = 0;
> > 	if (X86_MODRM_MOD(v) == 1)
> > 		*imm = *(u8 *)addr;
> > 	if (X86_MORRM_MOD(v) == 2)
> > 		*imm = *(u32 *)addr;
> > 
> > 	// WARN on MOD(v)==3 ??
> > 
> > 	return BUG_UD1;
> > }
> 
> Thanks for the example! (I think it should use macros instead of
> open-coded "0x67", "0x0f", etc, but yeah.)

Yeah, I didn't feel like hunting down pre-existing defines for all of
them, but yeah.

> > Why does the thing emit the asop prefix at all through? afaict it
> > doesn't affect the immediate you want to get at. And if it does this
> > prefix, should we worry about other prefixes? Ideally we'd not accept
> > any prefixes.
> 
> AFAICT it's because it's a small immediate? For an x86_64 build, this is
> how Clang is generating the UD1.

So the disp8 immediate comes from MOD==1, MOD==2 has a disp32. What the
prefix does is change the size of the memory being referenced from 32bit
to 16bit iirc, but since UD does not actually perform the load, this is
entirely superfluous afaict.

It might be good to figure out *why* clang thinks it needs this.

A REX prefix is far more likely to be useful (upper 8 destination
register for instance).

Anyway, it seems to basically boil down to needing a fairly complete
instruction decoder without being able the use the normal one :/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240628180441.GJ31592%40noisy.programming.kicks-ass.net.
