Return-Path: <kasan-dev+bncBDAMN6NI5EERBD7KYKZQMGQEXQOLJ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0AB90BD61
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 00:13:36 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-dfef7ac17f8sf5682255276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 15:13:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718662415; cv=pass;
        d=google.com; s=arc-20160816;
        b=hm1B6DADEz29lvdgIagyWZvvR6KVRnTy4An1NpIG0PVfb74yxO5OsgNLx8Sm+dPdD7
         1WG/pSWJwZHgaQTZXvxwrKoRvt/DxntWvpgcUQYw22/CEC5xFlS8isb+6Gyk7HqBBewy
         fmKHlNIVm8YQuoyFO5Ll7mrW6CqawogbzBv7YM+IsNC5NIn2QG5WE83HgQyIdyYAIAup
         UrmAiWzfdtyC593ytCz/LGVyTZPbR7yqCF+E7skgjJvqFJB2uPGs3ZPJtTbErYmCSANS
         gn1viMtkTMLDzCumo/GfJ4Q6z2S7NPceNqV8djbPrQWKzItUF9JgHMhhKjNUweOr/XBR
         6y9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=QLTwzZNW9Ka73JcvngeFVHyNiYPjrrEJcRyZRbfV6ng=;
        fh=nDdVZBL5Ia0hPlYSEdJuwlpbO0IVC9OukYjmBz9kPic=;
        b=m487gcLOtyoRk4IEVEks5LN6TdoAr+bqq0nugkVtFILaGyxdtAhxyWiFX4e16QNxUo
         990y+vqXsC1uCMJZ2XXVHEA2sgkWcE04UcLQyNS9gDKBFme5QnMYRCpQM/AizUhGxeEj
         aEl1AYmGPFOokb8qBkkmDdsxWvG/F+R9majley8QCkPbr2bW+F6NNFweTha52lxd+iCv
         9xUBDp5qrzN+oJpZvLy74JjsXp3mYQw5X0ovfWh1cWwYzdN7d2laJrgtD+M5jItoonjB
         wNXSGh+S9fqMf7mAV0a7B2OdvRaoym0xYVt1HGqTmgpLaH2Ew4fadVM2ffMp+mAqCsKv
         mJ2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cBZMNq+r;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718662415; x=1719267215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QLTwzZNW9Ka73JcvngeFVHyNiYPjrrEJcRyZRbfV6ng=;
        b=AhCu5gilj669XTd3/hpKsWk2tFggl4aK6Ixc1PgQOMNZZ867aZ+5VCvbDS3rxQ2Y/9
         B5RF4fuNVytVB8x7Mn6Mzf79sUkgLr4/IHvd92LUAPiVp1dLOLmBMbxXWkFWqUBbD5vw
         MvxMW2qvrEkEqnUx7tmqBaVj8NQDS6iiTSABGPOy/ebdDc0wDdOVqBdASSAWkYSKjVz6
         jYw72GCDVipOt8OcPAX5uQBBu1mGhvOtmz0kVY8RdoG10zZXDgw6itHIB5Zc87iO+Co8
         z82iUwFyiOLZMewEePd75inaCwsqzTEMDaNpI5+u1yHA1i+2asiP3CVIYTpQ8gtQKpPx
         3O3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718662415; x=1719267215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QLTwzZNW9Ka73JcvngeFVHyNiYPjrrEJcRyZRbfV6ng=;
        b=M21xn60UQAtdlZjhGq5hU9r4uI3Ex3yonQDECIlBhp+KF1IIPU8WNe/1kvMd0slkWq
         kADswsKxFDU46ic8DQ+UQCJdeQRE0eagMZyMabHNwBxCxulZBl9c85alRScmchM7QC0p
         1SFWXCQxmKpV4U3BAT2EDNUKS8+JNiNQ+DvgVFn+/jGNPH0zEuPX0sEAbuVgYxFFU4uE
         E+HcgnCLQ8PvkrT/cTe8ZD2xS90PUPb4BhH7OJT3BpEEPTnfWYzFc/1U276n3qo4FLoU
         wKp+LTtcRXSJL/wYpSaKLWjf+86YyJcnLwiDO4/ldWzzNr5B/E3p1XkGofr9Rob8+i4t
         pe4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEg4htjOHuta8dAnxM0Y8in3lmeZmRW2urG8xUIGPfkYeDvITcRYcDaA1LMA9VX56/ul7NWpnq7OQAiVgtvBeWwL8ZpIcNpg==
X-Gm-Message-State: AOJu0YwWPE1MBJ+cth6p48Kg+WHlt1N9HlnkHiFlR+vCwRsSN0NmTCkn
	l1FYxFDO5gJVwFsbIXRnd9teMvYuwBuanv4a+bQBIP144pWTQ11S
X-Google-Smtp-Source: AGHT+IGzxUqnBAocavj59+oi/ELZwpxYP/MT1nBNVDJ2qxEaxM7cWJorlrKpOSymBpQ0ZAEg/fgKcA==
X-Received: by 2002:a25:3dc7:0:b0:dff:31fa:4ab6 with SMTP id 3f1490d57ef6-e0221d94741mr712702276.7.1718662415477;
        Mon, 17 Jun 2024 15:13:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:150d:b0:dff:2d92:d93a with SMTP id
 3f1490d57ef6-dff2d92e6eals1958048276.1.-pod-prod-00-us; Mon, 17 Jun 2024
 15:13:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGzJxZRvqchAZRREy5pB0DqZSmCshDaS8/p1K86iIHmu23r2DlzrB16ph7TIaRjnYQHw4tJwowJMAHa52rBr7HRVkG2TlJ0A31Xg==
X-Received: by 2002:a0d:ebc3:0:b0:61a:e557:6ce1 with SMTP id 00721157ae682-6394868fe97mr6868447b3.1.1718662414287;
        Mon, 17 Jun 2024 15:13:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718662414; cv=none;
        d=google.com; s=arc-20160816;
        b=hWRtge6PVIbl5WJqV9fEPZmRPWGlOlRrCVy0GKk1Eo4cY9OsZ9piPveB+9FcrgHzkO
         6L7slhUElGZydmRGlPJIHxop3b86IXNVYsFtOtCNQwiApM1pA8OvNN5FbCw1b6USrs1S
         HYs/a6d6TGI12NIhdpMtEhxaw9oniNKrPjTdH+CXze/a/9FLY71ZHo+bfZbg2rKMMk+R
         GarIUw7CUS39dUjaPTsnw7EZV6drOcXYxKFInZImz3nvEjNqNHZXWiD+Er+LMiV5xeWv
         Qf8NypxGwqVqZj5fF122NcAoCkyA6+C4/AV7gD+AUmgbxp7pej3zZGDqiOuSZKF/Qwq7
         /8zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=CIRabLYRMR5NpCpWntKKTO4pVGlHUQzV4X+BxKrofPU=;
        fh=nRBybcRn8aorR6YZ7WPuOU4KxJuSPvX235NAM+tg+0Y=;
        b=ZC38DZ+LjIOWwdo45tliw406/NqLMtkSSALZPnTwQauvtw+eGHvxfTMXaoFNQ/R1ZL
         gIpOTb2VkVBJlu5w9571xwMdqVt7nBUgJdfyPXoXMWHBsD2ioekvqx2DlDEUmpQV933n
         2h6+7j8U5Rie1HhkDh4OgdmTeR/vNm2KaLTpGlRlFqAx2FQq4yefJmJ7Ug5fMeBlDBeY
         QcuoqA7cuY6cGVFiowk1KTIZaaeilli9a4VGtA7w7xCbRfeuTZoaCuC18J12njhOkxBa
         +3sdMejf3qfJKf2sHx/bhcX3VgNhXZJcE35GjN0ekSfY4X20jTJFmFQVys0BUQ3T45TF
         FLTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cBZMNq+r;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6311b3fd52dsi5027757b3.4.2024.06.17.15.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 15:13:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Kees Cook <kees@kernel.org>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>, Ingo Molnar
 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, Marco Elver <elver@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Nathan
 Chancellor <nathan@kernel.org>, Nick Desaulniers
 <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, Justin Stitt
 <justinstitt@google.com>, Andrew Morton <akpm@linux-foundation.org>, Rick
 Edgecombe <rick.p.edgecombe@intel.com>, Baoquan He <bhe@redhat.com>,
 Changbin Du <changbin.du@huawei.com>, Pengfei Xu <pengfei.xu@intel.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, Jason
 Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>, Uros Bizjak
 <ubizjak@gmail.com>, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
In-Reply-To: <202406121139.5E793B4F3E@keescook>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
 <878qzm6m2m.ffs@tglx>
 <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
 <202406121139.5E793B4F3E@keescook>
Date: Tue, 18 Jun 2024 00:13:27 +0200
Message-ID: <875xu7rzeg.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=cBZMNq+r;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Wed, Jun 12 2024 at 11:42, Kees Cook wrote:
> On Tue, Jun 11, 2024 at 01:26:09PM -0700, Gatlin Newhouse wrote:
>> It seems that is_valid_bugaddr() needs to be implemented on all architectures
>> and the function get_ud_type() replaces it here. So how should the patch handle
>> is_valid_bugaddr()? Should the function remain as-is in traps.c despite no
>> longer being used?
>
> Yeah, this is why I'd suggested to Gatlin in early designs to reuse
> is_valid_bugaddr()'s int value. It's a required function, so it seemed
> sensible to just repurpose it from yes/no to no/type1/type2/type3/etc.

It's not sensible, it's just tasteless.

If is_valid_bugaddr() is globaly required in it's boolean form then it
should just stay that way and not be abused just because it can be
abused.

What's wrong with doing:

__always_inline u16 get_ud_type(unsigned long addr)
{
        ....
}

int is_valid_bugaddr(unsigned long addr)
{
	return get_ud_type() != BUG_UD_NONE;
}

Hmm?

In fact is_valid_bugaddr() should be globally fixed up to return bool to
match what the function name suggests.

The UD type information is x86 specific and has zero business in a
generic architecture agnostic function return value.

It's a sad state of affairs that I have to explain this to people who
care about code correctness. Readability and consistency are substantial
parts of correctness, really.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/875xu7rzeg.ffs%40tglx.
