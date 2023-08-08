Return-Path: <kasan-dev+bncBCF5XGNWYQBRBNPGZKTAMGQE3ISQC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97A00774D08
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 23:27:18 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-56cff6fe7edsf10347605eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 14:27:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691530037; cv=pass;
        d=google.com; s=arc-20160816;
        b=03Kxb5SZ0qiWi+HfDBxyxMsKkFsuPWx2FZ6wtWjXut7EOLtb8IFew9E5uDkPg2dekx
         bVJ0JAIVuKTqqOR94zl9V+TPR7rI2bUfk64Cl244kDpXu/uVnjYf+VUSsqX4drAAYZrL
         +Dnb+9I1XuHptmssoSQM9Q1IEB1GZtPNqQihjBnSIK5/71w7JvGhVZeecP53bSV1fCcU
         9VSCP1hfHqGTJ1Z1ROOXwbjOwIwzl5Ko6MnB1BmASg7nt2263xmWDRzOJJ/xo4gSkUGn
         yMQueR3gL6LoXW2gecmi66UQOeeS9+S3/6zBDXbifzwSgp3FRArOIe0Ndd3Zq+kXbcI2
         /HTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qVhphrPN9Y6siOooaTiBfM8hgnpEFuqhiE517B3syqY=;
        fh=wbVHkFgczhdcNi7gKVqeUJ/ydt4wQT1gN173UJJyiiw=;
        b=M2DEGujnxEieYtQi+URsmDGFEbJiiXSwwfk0RhHLtm6/F97sTA4c2vBFaOBY7OYMg3
         jDIcLWMej4fuyCEe7GZW57RFx+4Bgoc3JgQg7BsH0Uy35WNvP6kmEif30zpzFmvpWVcQ
         nT6mzv5vsUhs454MWr3EFd2EwMXv8VIraUlsdA3sqgfd5f9AoGRGZvzZE9F89fnzSLyJ
         9KtPI0AZiY8SMR1dtXm4e1IixZskKS0heuLAc3hya+ZULC7aA9KCgE9Wb1hxOiBnqS8h
         mqtyQIOGZuNZbCR/9onRqMj4R4x1/VQIaBBkGHya1zeWdc3fQfTaFOMuP5TCmgGpG0zN
         gmRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=F+HSs+30;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691530037; x=1692134837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qVhphrPN9Y6siOooaTiBfM8hgnpEFuqhiE517B3syqY=;
        b=Pe0FftBjQxD2cHkDA1jMsD3lkNNvdvxzbud7cFF4LicyxABL173HACSAtGvYZg0igw
         Hn8Zwq/V8ipxMwWifBpYIVc/75Snza/LBy2OLM82dPhrosDBkeIqxGOV75Wn0vTgnA7k
         ZKe0YxR219LFWDkPVCHfNLUW+GetcvGQEXePzEU5hrQZ+J1q6IAtztBPNpU7b1nHYxlI
         iZ2m6t1mQumHVX+Q0E04tH1DbDpOCsNn3U5klo6PwSsSfBzIQbxk7Ywqvb12Wop8Knpx
         /Fit0Sqe63ICaWWE5s1AATq5l3DKtcQt22w9Op3Fq9NBnTJ1+atraxHqFJ1B4GPZ9y8l
         nKvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691530037; x=1692134837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qVhphrPN9Y6siOooaTiBfM8hgnpEFuqhiE517B3syqY=;
        b=UnqToQQWSmdyJGk8lzKkcrafoN6wfdk0IUXRG7GiWomG1M4XcAXbfkA8/NJDSJrA+V
         1SlNe6pQH607wgCQQ3dpJlnbqG3mQ6QieAF6CBjt/4sB6LTNPo+/9w1reYALqqMt1vma
         KVO1GRDYhheqcOdZ6GiwGR+QHDsQxowvIggRDC6CqNY1Li5HNYI12Dv8an8JSEhurRkI
         7xR7fZm3RrRFVyteCQU2aZjOdY5J2tO6RcaP0MdLbaLCbQwIGdv2uvC314ekjDIMM6lU
         FVNzuKw0mTc+r5qaDt8MS6ksbNWD5FtbO0kqlfChF6ogIaRUvBeL6MiwnXJrrYnXUTG/
         hHOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwIOO5IiwNX3ozSk/9UnShyUxCYS9v5jo0LIFz9wXZ7/5/cHRHv
	Wc1PB7oxaW0NrukLQmYoWVc=
X-Google-Smtp-Source: AGHT+IF9oNIE7acN0kMQyldcLYGfIOY1kA/A4Re9dBI9zaR6WGHRpR5NJZcfadIGLBWAZThJ4VN56A==
X-Received: by 2002:a4a:725a:0:b0:567:95:a0e5 with SMTP id r26-20020a4a725a000000b005670095a0e5mr882255ooe.0.1691530037321;
        Tue, 08 Aug 2023 14:27:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49cc:0:b0:56c:688e:e115 with SMTP id z195-20020a4a49cc000000b0056c688ee115ls4654487ooa.2.-pod-prod-08-us;
 Tue, 08 Aug 2023 14:27:16 -0700 (PDT)
X-Received: by 2002:aca:2b16:0:b0:3a7:1e98:80ad with SMTP id i22-20020aca2b16000000b003a71e9880admr941887oik.9.1691530036795;
        Tue, 08 Aug 2023 14:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691530036; cv=none;
        d=google.com; s=arc-20160816;
        b=w+hSG7TCAWBLQLJnBz4err98uLDoVP3ospOu9ktkyW2pzsMXpqr/+951FIjZ0s5/g5
         jUqEqX8m5B53ybz5QlBHcVFybt70+ki1WqhE3fCA6pvsJt0Nq7KgD6f/z6tgGrLG/uqx
         12t2ZMGHP36MrZcnUilZ9t1+JkUN3Aw2up//yqpsQMmaX46pUMeVES5g6fast6zPSY1z
         6bU4lfymsdH7Y1Ml0GSASyS5xYNiormggR9hfnr8MDM/XJwHI0kIiDJbOnKeE/Mv9hfh
         J85rl6I3G5RLamoTFocdUHa1tGWLrdPEwuM+AfYormCbsWdrJJVU+w/kcn6lAHOPYt40
         N0Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WblHbZVi4y1TIh0is8Z580iO5wWlNJUK6HXQ9JjhgNs=;
        fh=wbVHkFgczhdcNi7gKVqeUJ/ydt4wQT1gN173UJJyiiw=;
        b=GofI41DLC1uNIVEu16CoRnAxYtU+qPmXHHUZIc0eE96PEHtd2S9IxyHpw87dJHRXIj
         nwdw6bqD8AdkXR+rcxKX/w51bGdd6LydV+vtFVPHFKvcGBG0gennW7asjYLT7Uw7W25a
         6+drE2tSJz6HH/D6ysa3U1EGYkrL9oTCOy9AiyC1RxcASnHJHTUmQs3mjUnhhCM0XRoU
         PLii/4ghZM5zXDKXOFAuC9pgbCIOLFnUlVsrCa6JND90RcnTFgVg34Ce8NofzUES1oxU
         H5rFe8H5GG7SMCtcHOZfO7irnJk/DKRfZ5m8J82EAmiAZ1mW1Y5y/RmGLZOahSuWvUKV
         X1uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=F+HSs+30;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id bl10-20020a056808308a00b003a747d9498esi975877oib.4.2023.08.08.14.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Aug 2023 14:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-564ca521549so3189554a12.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Aug 2023 14:27:16 -0700 (PDT)
X-Received: by 2002:a17:90b:358b:b0:25b:c8b7:9e5b with SMTP id mm11-20020a17090b358b00b0025bc8b79e5bmr680387pjb.31.1691530036117;
        Tue, 08 Aug 2023 14:27:16 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id p4-20020a17090b010400b00267f1455d60sm1328pjz.20.2023.08.08.14.27.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Aug 2023 14:27:15 -0700 (PDT)
Date: Tue, 8 Aug 2023 14:27:14 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
Message-ID: <202308081424.1DC7AA4AE3@keescook>
References: <20230808102049.465864-1-elver@google.com>
 <20230808102049.465864-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230808102049.465864-3-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=F+HSs+30;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Aug 08, 2023 at 12:17:27PM +0200, Marco Elver wrote:
> Numerous production kernel configs (see [1, 2]) are choosing to enable
> CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
> configs [3]. The feature has never been designed with performance in
> mind, yet common list manipulation is happening across hot paths all
> over the kernel.
> 
> Introduce CONFIG_DEBUG_LIST_MINIMAL, which performs list pointer
> checking inline, and only upon list corruption delegates to the
> reporting slow path.

I'd really like to get away from calling this "DEBUG", since it's used
more for hardening (CONFIG_LIST_HARDENED?). Will Deacon spent some time
making this better a while back, but the series never landed. Do you
have a bit of time to look through it?

https://github.com/KSPP/linux/issues/10
https://lore.kernel.org/lkml/20200324153643.15527-1-will@kernel.org/

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202308081424.1DC7AA4AE3%40keescook.
