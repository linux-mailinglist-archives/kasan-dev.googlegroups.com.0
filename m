Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBTF2WDBQMGQE5NPOXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id C7A7EAFBB9F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 21:17:34 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-32ceaca46efsf7655701fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 12:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751915854; cv=pass;
        d=google.com; s=arc-20240605;
        b=bTyq16TcIc7tMILj6nPraCymvatx1xbavflFQch9Qs3XVJ8MX5miw1VEcUr+1jAdIg
         vUBF/h04fLoOjFpyvZ4MDEpPaPEEJS5ohQrk/yf4l5ll3nfWqRPdnkZ3UrwGbn4YTNkW
         LQk0V0Qn3MfwoAq8PDPRlwg8SBpTnro4UXrH5KfaCyRmFLdiHPtPYCdRuQOenrOLIWWH
         2aMOiK6jaXlSfWgFWSI/bbzwyxN/p8XDDal6vxeF9f8FwuITNcoh9s25XoOLVgpQGG35
         +SaRDCZ3zc6be6K2kCYpaF8AuGgdJQ8L1JyIQ9UzyVEwogtlmU+W7T3Nc3/NUpAXynpb
         C8wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=5YQo8YF8pUP60pSwi9AwyvhVmSeuMR2KyAB1xedWfdg=;
        fh=FRg3JN/q256a6y+bBF9nCeCH2NXhp/TVODEBzeCvrIU=;
        b=lNRT1YQG4HdbLfa6FcgCZvLY8IWMtKGkpdGo20ehIGZMz3ZT2q/T9Yoc32Int0QD7Y
         gaPt02bparM7VwhYItFh+JZFMUAScgOPVNr0B9StdZ21Jlfcyy+7TBu1K8S3FhYIVfqg
         gND2wSIF0FGxcPPL00NThxtB3WPj1Ai242X3a3G8MQ6Mt9z0yjiFHWzZNINp650RTKOp
         zJaZkOdtcElvrj6Xsi+Qmt6qWvQF5wg1Z3Z2o7DTZc4uH2v+p9C1bq64erJKhUxiNXua
         qZmvf8JBZN9NigAWVKSLIDo2f3UB5pS0ui0g0vpIz+LMTe5X8oeKB6OyWVR0OvAUCrOS
         6dvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Dp7991pJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751915854; x=1752520654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5YQo8YF8pUP60pSwi9AwyvhVmSeuMR2KyAB1xedWfdg=;
        b=P6pwpYCtkJWev82MSHJCnLy8jtZbZ4gcp7RG6lAcbzlDw5zzl4zoCnexkguhXb4phj
         AKagYm6J1CkuVz8e2am/WUYlNARgyHY7ktpPGvfHAXOBmY0Kk207k2v3YTmW5LHWwyYi
         u7DYPjlBNWrA03CMChGalG/q+BdTucDzIkrXQoYARJHSMuUe4rWWqTnuhLln8CxsS3EB
         yuHeVZFCVYkeIxMQdxgUTvg07Xx2ZnDvSRLpUd9UIsdl1M3zcXTFmK7W5iNHgO1azTYG
         zci7M8BLKDzOF9SUzFsxUeFkYnRDuA8WoxZkKohvoHidk6qkioPUEaJGCD3+QOBbsoTD
         uWTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751915854; x=1752520654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5YQo8YF8pUP60pSwi9AwyvhVmSeuMR2KyAB1xedWfdg=;
        b=wLGWdMIASzBm/eDG/IDylkIX2ZQWwIb/0tZaxUhAXbmcZKDjaXF0ftnvZj9A3nhtRW
         UWmETnCY+UN3ROJi+udDAZhrTMixs8H/SP2dBEzR6q3fXaUdyGajuqYlXLvRaeXgK6ld
         En14AGJKkf4mnPDdjuov1bIC8wrx3gFeaOkJyNL+/s4NOOUp0IEZDiU7JtWibm6hRFgK
         lLn74htN4TiRxRBC6jMHzeofj9/zplyFYYSZGGO6KidgJKS/mjZfOr1xzv72bizdVKuv
         4niqQiYE9PPidpFZvx9VvOPzC9XD7zswQIhCq94bdNreRz8//BRRqN3m6GM0QEIJqVv3
         xlhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZIhIHKgX8vHW+mzTrSZCn5OnArkJpwhWwp7JlzIfhkiwexEELrDvYa6BNLokgEGlQ3HYdxA==@lfdr.de
X-Gm-Message-State: AOJu0YzQ20PyCl4il6vJVfxFphHy4+g+tZyXM3yO7YqfLZVtuXDfiJ71
	dDj3ovsnCeR9sEaJ2nOQFxKpTlu2jFyL6IfZZDRiZjTqquE1Mhgqvox8
X-Google-Smtp-Source: AGHT+IFVnZZ/+y8gEkVpKW47xJY7BPSUj3zuTqpvIOZe6RgV/vqEFIxLiCE16nGo+aOeNoBroSPFjw==
X-Received: by 2002:a05:6512:1049:b0:553:28f1:66ec with SMTP id 2adb3069b0e04-556dd6bca69mr3786380e87.31.1751915853674;
        Mon, 07 Jul 2025 12:17:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc0IUtWLKGd3yIHUSSVBqnUSYAlxVznCGblG7VfzDazpQ==
Received: by 2002:a05:6512:650e:b0:553:2187:b4ff with SMTP id
 2adb3069b0e04-557d30a5752ls866283e87.2.-pod-prod-06-eu; Mon, 07 Jul 2025
 12:17:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUr8TQ+jlEv6JqcZrG3CfzjfVqDHyw3rlmCHh2BvlFyKB2iuEGPxMiLR7rC7mpdSfpS8YlASY+kf/g=@googlegroups.com
X-Received: by 2002:a05:6512:3f0e:b0:553:a32a:6ca with SMTP id 2adb3069b0e04-556dd6bb8b4mr4904169e87.32.1751915850129;
        Mon, 07 Jul 2025 12:17:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751915850; cv=none;
        d=google.com; s=arc-20240605;
        b=CUfvVWtgZOYPqTRuF8KLgbKd0EJifdC6CtQtd0jXgYN9wEJbnulzKoYK0DyDUN95Jf
         FRJHRweVFJE/riOy791n7pVl34arX4dJUuCYQoopdwIm0FOv2voGk1wnqlFRFIXIHtoT
         A+gC0hUmiIqA/Pj7XVx/GaO0UGRJvIEg1vt8/Gxo03VIEtEPW5gRWcLJtlBEo8JeXgLo
         ofLVAU6/QnnyawzDYJAaoSF7657fcHHeDW8P6XUQOo6McoKMh5DCgXNXF6peE735Tl1g
         tudc0iJku/vvaGDTFM96BzrprOuSp//M4LJRGv4iz4jUlMR+lM6k+yUTL/HTZ9F3Wq32
         TygQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ORZDLd02UGkkbh45cfJ5kZRWnBYJOZszPOFyiadW67g=;
        fh=RF7wFaMepo4j9/lTmQA5mo/SZxWoyAOFM6HLCnmcpWM=;
        b=DCKBiAy1wVifOagOS+HKLgrzTk3UalkqLGNu14xbpx6+ybrusqZ+P5SsC/eyx5sQZN
         zT3ubjwxMoos0AYNU4fYi1Kg2+flzfDNVZg3IT1as8wshslf5tE5PwFBwLI7kwWQMtud
         FqzBaKNbjv8t/6k3CJm3flK74EsFQp5MgKdY71lQRhfPgcY6UoZiuJ9XVQ4oM2+rFqwK
         IREz6ZklVSaspUU8HhNcIDtnqUmdBHJVSjW+Zca/rbuGU8WSjb6rfAGi9KrNo2r2BggV
         jM0/IEKuhQacAYw2JJMe1SDI7Dfv+4Gl62PUJsoMqT4mpto//BQ2WpApB+2LoIRHZ4ym
         Pt7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Dp7991pJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-556382c29f4si151560e87.0.2025.07.07.12.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 12:17:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id a640c23a62f3a-ade76b8356cso651026166b.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 12:17:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWi9XN5KHmqkOH31DHt1gsbb4x//4vbvPvLKJQnQG8kU4neiLQE4djNurmtEjCSeFx8S5xZoYQE7Vc=@googlegroups.com
X-Gm-Gg: ASbGncvMsVkaw5rlVuRX7/z9qVyNjGJNMNH7vb+PQch+7Fdn3yv5R/SlwcGZsnbs5qY
	KQRDy+eAj8CSyMxRrWG95dxcOM1tpErMAELi+K+Wkh1hHFrUFcBjqJvC+flOWp/+t4iACPRjhG3
	zHVH1pF6kS54jvUTzIjZOfs/IDbSvgUqIL1ibYNLBDnQfEkTSiqLIj054hVX09FYh0Y11tvHf0g
	2dFqBqeOR5MYtGlujUHMYI/aY8mTK7lf7cQcTtf4RRuuCfyE9IiBycAv2yIr5CYl8+WKQbmAugT
	ZQKz5X9brjq99ST2XtVdyuT4Xr39+qJYWWZSGxZ5PYrxcBceNbPAJLpkzYZu8W3bn4AIgmOTZa4
	kl6KYU2Y9sjFDRF7BCiKb0RpG9yq6avUvoiR4
X-Received: by 2002:a17:906:6a08:b0:ae3:c6a3:f833 with SMTP id a640c23a62f3a-ae3fbcb576amr1405141966b.23.1751915849316;
        Mon, 07 Jul 2025 12:17:29 -0700 (PDT)
Received: from mail-ed1-f50.google.com (mail-ed1-f50.google.com. [209.85.208.50])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae3f6ac6641sm767141066b.99.2025.07.07.12.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 12:17:28 -0700 (PDT)
Received: by mail-ed1-f50.google.com with SMTP id 4fb4d7f45d1cf-60768f080d8so6624960a12.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 12:17:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWghQdG3T/qh10N94EOi2PQeInSFBc/CcR/i3yGvGlhQTbRIOnDvL8s9mO0GjE4DcGiIi6DMvoTIF0=@googlegroups.com
X-Received: by 2002:a05:6402:430d:b0:607:5987:5b90 with SMTP id
 4fb4d7f45d1cf-60fd30d6669mr12436985a12.11.1751915847772; Mon, 07 Jul 2025
 12:17:27 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
In-Reply-To: <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 7 Jul 2025 12:17:11 -0700
X-Gmail-Original-Message-ID: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
X-Gm-Features: Ac12FXwOfsR2-wc3VkxaTo-SkUQ3qs88-iLy7sw-vzL7AWJu7PpVDNuYiHFuVTo
Message-ID: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=Dp7991pJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Sun, 6 Jul 2025 at 22:06, Alejandro Colomar <alx@kernel.org> wrote:
>
> -       p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
> +       p = seprintf(p, e, "%07u", s->size);

I am *really* not a fan of introducing yet another random non-standard
string function.

This 'seprintf' thing really seems to be a completely made-up thing.
Let's not go there. It just adds more confusion - it may be a simpler
interface, but it's another cogniitive load thing, and honestly, that
"beginning and end" interface is not great.

I think we'd be better off with real "character buffer" interfaces,
and they should be *named* that way, not be yet another "random
character added to the printf family".

The whole "add a random character" thing is a disease. But at least
with printf/fprintf/vprintf/vsnprintf/etc, it's a _standard_ disease,
so people hopefully know about it.

So I really *really* don't like things like seprintf(). It just makes me go WTF?

Interfaces that have worked for us are things like "seq_printf()", which

 (a) has sane naming, not "add random characters"

 (b) has real abstractions (in that case 'struct seq_file') rather
than adding random extra arguments to the argument list.

and we do have something like that in 'struct seq_buf'.  I'm not
convinced that's the optimal interface, but I think it's *better*.
Because it does both encapsulate a proper "this is my buffer" type,
and has a proper "this is a buffer operation" function name.

So I'd *much* rather people would try to convert their uses to things
like that, than add random letter combinations.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA%40mail.gmail.com.
