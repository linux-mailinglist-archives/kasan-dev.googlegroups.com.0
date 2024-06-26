Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDGO6GZQMGQE5PAER4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC21919688
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 21:07:59 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-706791ae948sf5827577b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 12:07:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719428877; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiQ4kMNR1ZpcnuTjLy2pb0sFpgijbmiPOxvz+RrqtP5U8+0O3L9aqUr4ltVM+yeH83
         y1FYKEfQ4lzS4SlRb8X851X7vwZbMBuzSc06LNjHZ4SveTbcieV92LoSDmo5Om6g6zMv
         KC4S8odg+FUM+aGJVr1waWV3LNCj6e0s6rppdqvhVwA/mfdq9kXYmzvBtTtsr+lq/5/s
         EoA8/0ydeRpv9XyX6W/r3iwhw78wKANVuvixsnXHXUYqbbvix/3XNZCShFxrUMFAr9ve
         i+n6UpBvkQchDBLigoGH/fWYMMbffj6xT2K8NRkLI/YCnbiZ/psG+3Jt8/IXMFCUY3yG
         A/kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XMgKCgeEKp/axSi3+YLrYle4JCMuhI24jcjgL8HMeSE=;
        fh=/XVp0UPeSVoursm7590xx1xMvTyBEk+Bc8BgdU22Nyg=;
        b=FuuImHkKLaC36wH//5LS8yKxAPK80l1KgV1h1tGlud9WiBfEkbLjbkW5YRoflobImK
         9A/lfH0+VWUT7aC4iw47fzxvyP0TA0JWIRTqe5RS52kyc+Fj4MG5qwhdWVX+J1SEsQk+
         sFOQ0o01Na3YMzjlpiYp/quJA6+mhXW3rJ+oq5SM1YIYzl3CdtwrlxOgW2KQlyT+Mqt3
         BknUdJ1+huopeISkgOVLGxhPS9j8hPR1kh1vwJbu3IPn+63Vz8QD8sWig+CQeVhxAusY
         4zMEak3XcP/QM/YVquV6hujzDeUX6KqOcSqDCpSzOMKRB+3/7NswQsnCvVP91JJVL/e9
         iyPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jHTqRn4f;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719428877; x=1720033677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XMgKCgeEKp/axSi3+YLrYle4JCMuhI24jcjgL8HMeSE=;
        b=K6QIMc3j+ORnNtEY3xjE6CvuMW8v70X4LRd3ZMBqp+SdV/rMk+qxPxipQhOteYQ5Ct
         V8my0p/ywM3KUV/JUop868U/rvVTvQzqjQmOOf5QKngR7InDt8JMMsvuT+oeEll4s0Gd
         9pKZ45DoA+Pg8HCpXQmxXRvr4jl2IS4H9XMOh3RmSeWZX3ByfmIit4JQFHMUBwO6lDK6
         F9sQ67ErMQMY5HEqQBzAZOpk94LFwXNPP4yY0YJZgh+iQmGpqIs4EwyexTLUwpzhdrfa
         oIY/aVLrhkOVHETiHmZvEs4LcY/NH6Xws1CcYK9USxS9A2PleWfu5iJStH8GXqMzoBH1
         ajwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719428877; x=1720033677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XMgKCgeEKp/axSi3+YLrYle4JCMuhI24jcjgL8HMeSE=;
        b=BvM5thCCxeUmpaAnE+VqztU8PVHK6Z46goPTqfSze2pAdD8zoszy1VPea8YTZtR+OZ
         RGBsNamkz2QkFquy+x2VJgmnW2BrlEg18fLOR4qPoEPR4Lj6zezEeOjO9NDz/bWW0JOS
         dYR490sDMczD6DkVnTinfwm9Tt/U+FvKQKx4UzRyQ2JNFg2ThzqBJG0vYC9bHSuGYQb8
         Ma6bVA78CJvZ17wqM5e2b8PgRet+YLotgbNrqs/0eFvfDdHFqhCQMAU/o3wTaAl7gU3K
         9A6uwvtk1BpzkCLV+wtwOiY5hM/9CIIvNTJSNb4TpAYuMiuqkY16V9uwwQ49Yz+54JVf
         mQAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQPWHCXgvU8hEkTwIuNrYLTveGxoc+l0koZDIZbG9RXIJEagq/cx1CmCuSUJ0oiaAlDjfOUDtL1dHzhqzMTm7ser3eHso8Ug==
X-Gm-Message-State: AOJu0YyGicEkCE6aRHc50Wr1yTEXN23TabRffh3nWPf9tuXyPqNSGoIY
	KMcTaehfj9lTqoC8OKwRMF+775MdxfM2hqn+GJ1ztkXzoSQvXr1u
X-Google-Smtp-Source: AGHT+IEaRZOES2ZCb5w2IbxABSbRAoHa6b8LgiZJnQ92x8rzINSXB2ufn/soAf8GRBoHrekrRZwsow==
X-Received: by 2002:a05:6a20:1b0f:b0:1bd:21aa:df8 with SMTP id adf61e73a8af0-1bd21aa0e3bmr4972831637.7.1719428877118;
        Wed, 26 Jun 2024 12:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:3d48:5906 with SMTP id
 d9443c01a7336-1f9c4ee6708ls50315955ad.0.-pod-prod-05-us; Wed, 26 Jun 2024
 12:07:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMjpz7BufVd8nXAYlsyo8nJp2//QkQzMFxD5I094KEy9UzHExCeag0AZzHW8uJZJusLN5e9jbrUoraRwNmtNwbaTOT2QJmUEZMKA==
X-Received: by 2002:a17:902:f685:b0:1f7:13db:527b with SMTP id d9443c01a7336-1fa23bdb870mr123052155ad.7.1719428875956;
        Wed, 26 Jun 2024 12:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719428875; cv=none;
        d=google.com; s=arc-20160816;
        b=hM1IhXo7QYb2diuiV6K8zgW7HzSXwed6M2jbyvnY2ZJIidn08KGY10oEaHc6qD3sFf
         1Argg25OE0CXfuSb0jn9aHuSyFYIiwizeGyi0A6HCMlo1AK019bYRNTSMaDcz21lPyGi
         GdB0EcQKVKeAHv6VbvMDt/1toefDizA94A9h1AwHvl25JtUK4w1KOdWBo8AI3npcU9UB
         fiosINIaJ9b6uD69HXjg3Uqrhy1roXFzSaNw4Dx+r7suVHS0C9PNePOxbJqx2R+tsXGQ
         b73iFTkPwAp9VMCOqge+UD6zQrpQ/sDcJqaywobBImfn3FTHwnr2E/10piuuoSgTa8EW
         WtWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aA1BxtqP3MJs53VdcsjGWeF4jKNR2Irr+jBzhI7La8A=;
        fh=bHUgRRbmF6rAM6Rr1vzt2B/dXFtJR09rNyMuusLa5+4=;
        b=kDonICtb8TqGKdw6W9o9PGG5LcGh5yumOo5PcEAjZo91al5dgxh4uahKXwqdW8jun4
         PIO5/RgHi8UVEXrMkeYG0/9ypVPgsOB1gxpgMVB6xoqxj5MiyeZGdNOfSHCnQYBX5ar3
         zOEIpTwEVA89lIrw8AYZa/z0UwBK2GEK/ZRcohTLpUTalz/vfwC190u9AxhDH8B7o0/f
         TYdP1pfifdqahg55m303FPjdOawD2erjStKw/k43OR5UuIKrMCtA0YEPssczFgXiaWIW
         5PF2I9QQgqz0SljZM2cA28mPgtKhDmprAERnAed+ENDHOXstvaMWPM5bT0tQmeoRUglU
         c5YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jHTqRn4f;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb2ef06csi4444375ad.2.2024.06.26.12.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Jun 2024 12:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id D5471CE2C52;
	Wed, 26 Jun 2024 19:07:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D1AA9C32782;
	Wed, 26 Jun 2024 19:07:52 +0000 (UTC)
Date: Wed, 26 Jun 2024 12:07:52 -0700
From: Kees Cook <kees@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <202406261205.E2435C68@keescook>
References: <20240625032509.4155839-1-gatlin.newhouse@gmail.com>
 <20240625093719.GW31592@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240625093719.GW31592@noisy.programming.kicks-ass.net>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jHTqRn4f;       spf=pass
 (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Jun 25, 2024 at 11:37:19AM +0200, Peter Zijlstra wrote:
> Also, wouldn't it be saner to write this something like:
> 
> __always_inline int decode_bug(unsigned long addr, u32 *imm)
> {
> 	u8 v;
> 
> 	if (addr < TASK_SIZE)
> 		return BUG_NONE;
> 
> 	v = *(u8 *)(addr++);
> 	if (v == 0x67)
> 		v = *(u8 *)(addr++);
> 	if (v != 0x0f)
> 		return BUG_NONE;
> 	v = *(u8 *)(addr++);
> 	if (v == 0x0b)
> 		return BUG_UD2;
> 	if (v != 0xb9)
> 		return BUG_NONE;
> 
> 	if (X86_MODRM_RM(v) == 4)
> 		addr++; /* consume SiB */
> 
> 	*imm = 0;
> 	if (X86_MODRM_MOD(v) == 1)
> 		*imm = *(u8 *)addr;
> 	if (X86_MORRM_MOD(v) == 2)
> 		*imm = *(u32 *)addr;
> 
> 	// WARN on MOD(v)==3 ??
> 
> 	return BUG_UD1;
> }

Thanks for the example! (I think it should use macros instead of
open-coded "0x67", "0x0f", etc, but yeah.)

> Why does the thing emit the asop prefix at all through? afaict it
> doesn't affect the immediate you want to get at. And if it does this
> prefix, should we worry about other prefixes? Ideally we'd not accept
> any prefixes.

AFAICT it's because it's a small immediate? For an x86_64 build, this is
how Clang is generating the UD1.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202406261205.E2435C68%40keescook.
