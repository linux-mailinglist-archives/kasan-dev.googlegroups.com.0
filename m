Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBV7J5CZAMGQEIRIMIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id B8AB18D6ACD
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 22:36:41 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1f44b594ec9sf21136955ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 13:36:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717187800; cv=pass;
        d=google.com; s=arc-20160816;
        b=vTVqZxKoVMxY+qminBhfFDZCVhD5Q5aw4OG+Pmpsp2/YNnkJUDU8+gbtRIg4UUaDQx
         rI0szNIGlW8Gh5jyYjfBQnvB6FHmFZbkwl5NwruMEeBlXyoURA1mL2suBoih4bHZ75Kz
         zCYkArn5qY6CtIJasAQHSITLWKkq8UtMcfn7Jgj5SOYBoJaViAHDoMOATnqeh/r8/IL7
         /OgACaBxBU9B8p93cc+3xpPq/gwmOwzNqaXpeZi2nr7EZhdLWLMIrOvB+xUWFh+QVYn1
         isHJKJrwPU5bjXkmXiQBisRMxeyed0GM5d9olmLUqfoZHjontJXkfnzz8nRXuH9ymltS
         oW+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=Y44A0FcYJ6RRy9h4dStz8J91vqkarTsMh6YwIF+jdiY=;
        fh=DJdW4F81CVWtkHDsUItAyrQ/vBITp72LLOnhQwY72xQ=;
        b=sIcM+UbZOHfiBVUlgY0IUJ5p1B5NVFUdLo4njuc0iP8X0Jm70J15d/z0dInxN7m+iw
         2Zl82LvTeXkb7Y1vGr8CsE0GX+pbrCsyJome/QgD0/H4V6GdtRlz8FqV5o6Jb4J442q0
         uROtBSZRO8F2GrEgwq54WRjcDI87t6Ar9Fb2/+AywBe9QX9TqnIK7SZbM/tVQOT/K+8m
         fTA2ETpd6xxNvsktm0D2VxOjzGIbU60mJA1cYoqTNQCMSd6Tf+r2QZT9xA1OtCmyqZkQ
         38JlfFDGpWhPW1q9gJJrqNC/QNfuvyRSODNjefALTzesU2+TCeemcjt/1et5tAIH8BbF
         zsKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RR8up+Un;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717187800; x=1717792600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y44A0FcYJ6RRy9h4dStz8J91vqkarTsMh6YwIF+jdiY=;
        b=J7AzuOWWJDeAN6PSe9r8x6tDEVo5CGC2VNZxfrPC6Y1RaMGpPPwyK0VyzgZ4M0NHzU
         PxR1TDbUjzsmf3Wryw2sGL6IAx+9NUeeSmIBS+k6UIc9hZ1F0BQQzEVSVDwhrwOHY6Kw
         JSRn/OzFRihkYV7gR2+4WBL111cH8EqEOISPw8ZDoyfizSORjSGtzOpdl0q1i59Gqu6E
         TETYI0hJrIFEsGAgF5Y5+MsF/bXuQ8XqSqAzij4PGcA6FHN5CG1PSMApECAGFCvF5ev5
         DV1pIa7B1U5v3jPapJKktFZ6BzEBKJEkcXL1s3dzdJGCcRJDnFMJTdt8DgZB2JO5u+Qb
         iDxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1717187800; x=1717792600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Y44A0FcYJ6RRy9h4dStz8J91vqkarTsMh6YwIF+jdiY=;
        b=Kq6VEWAqRyG3N2HWMT8MXvPoFD7nU43C68qAxhWNHw4zqonsVvZuAGhxNn/wL5IoOh
         XGKMQAVH6DXfNWjhyqZzUX31SA/Nty+zKxvdv9S42/s8OnGi6vTuScu+RlxQCzE1uaeg
         V+qB2kD0Xi73LSqEXVXVwXlmUq2Jrskerw9BlAbdKnDJT0ko2NaLvLyzOnU3L3+KCg6J
         ZfyIezKf75vwQRPR0SO04rkieZkjH1tN3ij6sr/z3DB9MSUac78/0wwOli99LRYKUpNQ
         8Jx5K2B7+7XHK4lqDGniEyS/v1LxrpOkLP+6iWTEYMvYaNRz8rL25EQQBONpdjj05O4Z
         Mgtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717187800; x=1717792600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y44A0FcYJ6RRy9h4dStz8J91vqkarTsMh6YwIF+jdiY=;
        b=cETfkV5v+se0dSzvZP8p/hxljy7eqxdqYYVcroThL3A3SpM9XNDKxJdFR/0g8qn2wp
         6y8qYyz+TkrHGaujiLP1p8ron6ntXEWXJNQ9KgHCt1ei+fH9V9vWHpXOML2BKnh6+zJo
         rcOl0WYPYWKG7J/jpsU8k/m3T2oimgz6M/FgPFwXilQWgOXD+N2fVYK3UV9pY+TCSbOg
         V16DubC2d688u+picm8MmFg/TLLdGXXp+lJftOpSSLdOzYyLhrmg0X4bUp7hm43XPgNC
         tn4YMnULEUaTVbYcRCWBXWG+DYPwBs5XyTKXj2xGYNpbseXSfZdhzMbTaKc5l5LnPySf
         63vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOiwpC9oa7gnGCgENL0BHRngxvmVnEJGRyG5nBfDzRpOt2VImEGS4OY4l1l6jcSvdYbXJoKO33iFHFijKAkcVHU2871AN/lQ==
X-Gm-Message-State: AOJu0Yw2+/tv6BkARGm2CA8YDJNpT+F4pVl22YGn/ggutXg6R5bSRdh3
	9utXWz8OgJYZLbgFFGmuLTruDOUMr8/We6SKR/61woQX90RP5zel
X-Google-Smtp-Source: AGHT+IFFa7tetEmdtg/kGR6B2ba288OPHXJ9zWmw5l9t3qSmmrEggNRAApFbSJZ7JvdjPGsz0UdJuQ==
X-Received: by 2002:a17:903:189:b0:1f4:8e4a:b781 with SMTP id d9443c01a7336-1f637018b0fmr36128555ad.18.1717187799646;
        Fri, 31 May 2024 13:36:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb8c:b0:1f3:465f:da8f with SMTP id
 d9443c01a7336-1f6173fcf58ls17354645ad.1.-pod-prod-03-us; Fri, 31 May 2024
 13:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyArKSdgvC6zhnH3GwwgxmMcHG9bIpL+XnEZzD8NjcRzybUGBGWXooj65hyFJPLM6FpfE9e2O8pWbI3wdVq7O6vb31P1STpVrVAA==
X-Received: by 2002:a17:90b:4d90:b0:2bf:8fbf:e4c7 with SMTP id 98e67ed59e1d1-2c1dc572136mr2922270a91.16.1717187798250;
        Fri, 31 May 2024 13:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717187798; cv=none;
        d=google.com; s=arc-20160816;
        b=qp0lcYmFlNNS5DpjRV8LA6EGVeyTBtvifeErz4asrWgGGqwIF8dCtVKQkzL/BTa0g2
         ocD2PnQo10063LABk3GKrXEiTAkzFF9hAiibP9V1zwFeBPdvc27chlRrJoVdQzvsxh0p
         89xg230dkN6ttNOX/l3LxrCy0u7NjvUPdSOiLTEbACQP6V1WizZG1D2xxIm1UEQbr7JX
         eqGdLAmKwDIV6sROLRb6chlyLROTDV37/xDJhBHwMzibKvRmV7suQDoeVP21LWXr/Bz/
         1cOlpesup3AKX4VLRx8xosJFqDb7UFJNuqFwzLMAkgb6ponJb8SNpGYskA5sqEDtE9Gs
         RwNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=twLijwTOj4W6ARqqInAp+sh1XdnAFooJeHYSV2DKonw=;
        fh=H3CRkiRqkZGJ2tDkT6g2RRdjNrNngwHMU40Key+pEXc=;
        b=Okr1ada3fU/RWGQ/TScxi4qsu+jT8Xvekkj7VkP5vCj5+nYuOSZlsgPhjCYHTegSVg
         l4ZCFmBINQd9yzY1xRi9QJmHSk94j95SE0vTM1+ZsmZ6HRYyqke3VDNe6pxuMxmjSBGq
         xXW/MqP6YJ2NKnnwB4kqAAUPvt+lCIrpER64vFLJOeMuQJAAMmMkfeBEECcYoGC5d6C+
         8YgzxFrPsUeareKkcyqhw3EgktcHAZr5Lzmyhtz5cnWAEJvGbklsOXJIytdyGEkemCxr
         nMyEfm2jyiQrUQ77e1G59WPJQGcFO7uT1MKQR+A2Z8o7piEX6jGW9/EUjCAgGYEZeEPJ
         4lJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RR8up+Un;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c030fc8008si474602a91.1.2024.05.31.13.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 May 2024 13:36:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1f60a502bb2so18799625ad.3
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2024 13:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrRFAorbXpAZHuWXTcwsT1BuEp1lfxxH4livPwLsXfm0JRuQch6kuXMjALrSs3gvHI6EQrA/WLGa3TzvpEgRYLC/c1arzI6nrdVQ==
X-Received: by 2002:a17:902:ed54:b0:1f3:ea4:7ed6 with SMTP id d9443c01a7336-1f6370e66fdmr27847175ad.61.1717187797708;
        Fri, 31 May 2024 13:36:37 -0700 (PDT)
Received: from Gatlins-MBP.lan ([2001:558:6025:79:9460:fb03:8dbb:8b69])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f632413e63sm20862525ad.276.2024.05.31.13.36.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 31 May 2024 13:36:37 -0700 (PDT)
Date: Fri, 31 May 2024 13:36:35 -0700
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Baoquan He <bhe@redhat.com>, Rick Edgecombe <rick.p.edgecombe@intel.com>, 
	Changbin Du <changbin.du@huawei.com>, Pengfei Xu <pengfei.xu@intel.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
Message-ID: <5yx5aykf77x2gufpaf4nlrdhiqh6ioiqicazp4wq6dosu6d62g@xmj62qw7xa7q>
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
 <c068193b-75fb-49d2-9104-775051ffd941@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <c068193b-75fb-49d2-9104-775051ffd941@citrix.com>
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RR8up+Un;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, May 30, 2024 at 01:24:56AM UTC, Andrew Cooper wrote:
> On 29/05/2024 3:20 am, Gatlin Newhouse wrote:
> > diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> > index a3ec87d198ac..e3fbed9073f8 100644
> > --- a/arch/x86/include/asm/bug.h
> > +++ b/arch/x86/include/asm/bug.h
> > @@ -13,6 +13,14 @@
> >  #define INSN_UD2	0x0b0f
> >  #define LEN_UD2		2
> > =20
> > +/*
> > + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit=
.
> > + */
> > +#define INSN_UD1	0xb90f
> > +#define LEN_UD1		2
> > +#define INSN_REX	0x67
> > +#define LEN_REX		1
>=20
> That's an address size override prefix, not a REX prefix.

Good to know, thanks.

> What information is actually encoded in this UD1 instruction?=C2=A0 I can=
't
> find anything any documentation which actually discusses how the ModRM
> byte is encoded.

lib/ubsan.h has a comment before the ubsan_checks enum which links to line =
113
in LLVM's clang/lib/CodeGen/CodeGenFunction.h which defines the values for =
the
ModRM byte. I think the Undefined Behavior Sanitizer pass does the actual
encoding of UB type to values but I'm not an expert in LLVM.

> ~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5yx5aykf77x2gufpaf4nlrdhiqh6ioiqicazp4wq6dosu6d62g%40xmj62qw7xa7q=
.
