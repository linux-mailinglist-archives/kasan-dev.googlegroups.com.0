Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHS6XGAMGQEXXO35JI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IL5iMhJ5nWmAQAQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBEHS6XGAMGQEXXO35JI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 11:10:26 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 31FDF18525B
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 11:10:26 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-798541939fdsf19506167b3.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 02:10:26 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771927824; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mr6YBllZRsP+dkkkivo4pm3luusxkBR2bczErZa67GAYQs+UTqQdoYP8yVt/RDJSif
         xS2FNGvGI2Bm3nuBTOh5lfbG5y2iRXtSRN8xt6kDvavbgdP88QHll5ObmMoIuYDHWQEq
         TqI3hmeTo/2K+j+fcX4tL7l0f+5usyQWHD+W1Yg3uy/c+3JWtbTDOn16eCglWeHILFsC
         kteqmFcXfPgxmgoXV40MbWPbTjTKNPWt/7sKJVlzJbsPSSpiQanuZodebCAzWiEArpmy
         vUB8XCO5dtH8uB7cAWBmlMipmB00peTjScOFUyAVeqViGX5Rh+rBqPdcdipGXrYMQIY3
         +GRA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bLCkTtrOUwMlQzp6BF57BMw1htKwlGiJxIdQ93o5W+s=;
        fh=YrAfluhUlmZPHmHtwcVQXSSFyolF0IDoyCjZYninNSw=;
        b=UzQB3FRAO7NYFx/iItoDw3iJqKy9vd/w5oT504ifOD+zKeQ7aN4A9L4JmxtJI3bIc6
         gzfqghncZYr6gsESdi9C14Hnhadwo/jrMBNVmEJDeGrgvrc9PKwp5LAyoANW0fLZU3MB
         SHBQCo4tBGb/BwtVSxB2quK0kajXm3lpfrreJk9OR8GAbLID8NTIUSihJUF9pFXEQV8B
         rHvSOZQARkhLZOnC9EB/GJzlDOtO282DQEbXr4zbwdofnsCH/VZwM2ajcPqhlnLfXN8L
         L/KkNc3LeXngojgpRZw3WiR7kSXuX/PQuW6fgFQdEB+0pwSMqR5QUul7z2B24NsS4cyj
         BtDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m0Phm+Qe;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771927824; x=1772532624; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bLCkTtrOUwMlQzp6BF57BMw1htKwlGiJxIdQ93o5W+s=;
        b=CzWnYx9+ndWYFCkAfGjaTt2xlSsSoCopRAwkhdjUvCIPASjw1XMbSFE7T5s7gR0SmQ
         oB6NCrbXn9XiJ3vVqZbgvtdt8N45PYBjbe1PPnrzMR/CO58nrQk61oWuljBH/eS4PHXa
         8l0CpurOiXneA3gzXAch8IQxEloiacjWRWfqYDAKgOi3avo3iaIZXE7v/8u9FJCI30RY
         b6MJh8CMWgTgeOZ/JUohRMyZgXPbnQb6w54CjIP5ymTTmyfp0uazTo34ZNW7da1zqmI6
         Qt3wFnRq0c2wmpazwG6piUq7Ywp2OQnMxp8hukvnAdMHroeVu2L0uFvIa67MkLNQpPdt
         CGsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771927824; x=1772532624;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bLCkTtrOUwMlQzp6BF57BMw1htKwlGiJxIdQ93o5W+s=;
        b=G5dDpqOwgUP9dlE/nyCnjCcIol4Xbp6CI8yx+M+x//EYC9KeKup3shQF+JtY/pjSZv
         9EzTEwTkWJgp7WY2zSKrnUzSAAjPk3xmlSf0g1++Qrui+wFikeAgqNViNPLKclOT5GJG
         99GVr5CbexqHXxZ1R/1Qwknzq339FWHeeQQyDMGtKf7BL7bvb5JphWt2iEhHBiM3CyYG
         gX5WawY6cg2mDEr7k+HdOJ94PMS8OZnpIOfk+VKpMeMRM61KN1sT3VEmXdI+0XHertj9
         fURgT8FrxHn6YqTuk01rm7lp+vgos9pCBfJJkAtvyOaTuZf3IRG80WjQ9vGlVJthQGSB
         G9mg==
X-Forwarded-Encrypted: i=3; AJvYcCVoq/yqF1E+glWV68xFbYaW5nixhvURpDdkiCFJwFy/7IYgMdU8vPtHcbJJm10wS5fjnb5Y3g==@lfdr.de
X-Gm-Message-State: AOJu0Ywq/jKhywz3enYt5hNPQyYByBQ6fzPbsgth5iWJk5j7xj635rS2
	mDLv4KkQsdT5fPxu9g9eBU4VfpG26GMUIPOERQhuPDJCWe7WKfuLg0lj
X-Received: by 2002:a05:690e:12c9:b0:64c:9a66:9a15 with SMTP id 956f58d0204a3-64c9a669b60mr2346410d50.0.1771927824345;
        Tue, 24 Feb 2026 02:10:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ERdzc86A/l+rn6lF9jbbioPoau1QFOtL3zaS3nePA9rg=="
Received: by 2002:a53:d604:0:b0:644:730d:6219 with SMTP id 956f58d0204a3-64c0e8a9abcls10496766d50.1.-pod-prod-05-us;
 Tue, 24 Feb 2026 02:10:22 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUsVNqEmCBET57bViox8pBnsB8K940ct2JN+LFpUEzirG0bMmaeoDH1VI+IRT0bG2Kl/rDkj6HuLcc=@googlegroups.com
X-Received: by 2002:a05:690c:9c03:b0:796:39c2:bccb with SMTP id 00721157ae682-798291734bemr90564657b3.63.1771927822686;
        Tue, 24 Feb 2026 02:10:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771927822; cv=pass;
        d=google.com; s=arc-20240605;
        b=j0c1bZCrZPpFCIGexhB8V++xpqf5bsKOum90YOn2qJHszyvC04RhDNJBJX6MNTH8h4
         RaSL+nO3mFrBuAeFN4qH/PWL6/64m4HM1xYfoSmzLhBoPpxD+xkrA/nlBOgzxItbRZok
         bdMgo8/m3Y+Ot8rtgcxnB8KfuRLvWBzSRGPH+GBbDx8Tl+iFMW2qOqhPJ83xj18YDSnZ
         424eMRsUwqlGBCxeSmZhjMlS2Ui9Lq0Ax2pkT9cqQD96FZh/354ZvOCgENAU2PikOCMW
         f0z9WlFVC0JZ9qSH9G+epQGHo9CRBQsMvUCIoIL9ylpHj4by+vtvhJ+5BPNlo1bdDuHm
         meNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cU+7ICKZHFM5pmHnJJKLvE0nvJUxV3pF6UBqyGhCb3c=;
        fh=8cZEaMIY03rgXFFNb4BOWTOLeWMn6ZBEV0Qekzub5B0=;
        b=CXSxVV0sqEMWgzq1fRtCzNxoLb68pUBFG9TGu/DEDFeS3xrqs0GuN6+CpYPBZ7cEwx
         h06klVRqs/qK5a/vT2NmN6SskklwGuzad0Y3bQzry3ISe+40vkVHb/fCgIG4A8yt+33D
         4Bh0iJ57Ln8R8TH2n/TD3jJ6cFNlGitkdJUuN+Ji4kiroDs7GC2X1Hr8aT+kchxqsV4B
         HXW/hqEmJHMXmvFoUq8k4X3OZ+9xSQ2iLOqGTI5/D/xXsVHRa7zeNUor1QUQN2NC0O0u
         uNwARGAWFa4lJAso6jI8Y60kmFYhHIp/SziQXOqF2YMo3AZR7GvC2fUGo9yElDXaXBb+
         Pf7A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=m0Phm+Qe;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x122c.google.com (mail-dl1-x122c.google.com. [2607:f8b0:4864:20::122c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7982de98d03si3460137b3.7.2026.02.24.02.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Feb 2026 02:10:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122c as permitted sender) client-ip=2607:f8b0:4864:20::122c;
Received: by mail-dl1-x122c.google.com with SMTP id a92af1059eb24-12776bebe9fso1673398c88.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Feb 2026 02:10:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771927822; cv=none;
        d=google.com; s=arc-20240605;
        b=jpmYMUFYLeB1RloVSeYQ7YD7fwioYDb2JYbKpxZl9fIa90OpV0kUDqZBVIOx7171rB
         KkXmCXFeTQe7DGOW/MvXZ8Ho5qKTs6uPvEF09N9M+KhqWwLbCEZWfNcZAAATXo04z4CR
         rSRBBW/l5ZYUeXnDwxSqA/uIYKjnQPF2x3J3C1Ms0LIj/0EwJS/tV/QUN946lBq/4KVY
         1Cf0fc+tLiLdJIWulHGtGL314YmtPXy/yEZTWyzTEhKI822DZsM+mjVoVmw8AplGVwk8
         8osTzTBmkn6I3yCs8Urbr1G0IMVdihb8SP9kMBxw0VDs6uBmu2aFHw6xAI2mBBGfQ7Im
         PuOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cU+7ICKZHFM5pmHnJJKLvE0nvJUxV3pF6UBqyGhCb3c=;
        fh=8cZEaMIY03rgXFFNb4BOWTOLeWMn6ZBEV0Qekzub5B0=;
        b=VglUn19/wNXuMQlqmpkvvH0XzjJwDtlZpRsciROkvhGSLCK9URKpmuvYS9rQH3WJL7
         kGzdPIQtGapH7pNi5JIsD0zuaW/VMCUe+XoH6ZHLZMXGVVPudpt6Xdf9K7GmCiLbvJ8t
         YYaLd+oK5cYRjTDOFCvPWzyd5eKU57sgloc5fia0iYMtH2YTnaRmdLvrHlQBbbgER3ES
         aYEFc9WZpv+kC3Z9sOtuXz9Lf1XOyDVIDL2kBY9I3JfIgs6cbAWmdv15oxLtqmdKtj7U
         gVjniBLeys13cyPSijHVMZomeseZMSEGKaTMlPFhNuUsVUCv5i5fFSdjnEWopp/SU2i5
         MqPg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUQbXmum4nvG+zWlDADCz7noOr/Z8rRK1T6mPY5799GIHskIKyycZl+YWENoNIpMeSYd2b2COuIzpQ=@googlegroups.com
X-Gm-Gg: AZuq6aIEFXfy0mvavOoEDKsK9ZQGKQX5pXsqahcmnyPFQg/vZBAlxTxKpWbNUQgOleI
	nHurrobzOeKmwWBfY7amklDqrjWNTEA89x/dFZYXzbJnlVZ7K9tUpkw0v4fxc0DXArLXTrIqe2Q
	/qlo4ZmpZzuZNpkgCBX6WO0l0uNtdBx51Ov/eGfvVMzMoz3VNG5p/NeWy4N+sBaB+H5yRjeFBsU
	ePAW2xsTKzu+q/QbOrSs13vsgaJncF13KSGlWJDWbL3w0euDxqml5xFWHDLISJ2fCxjbf41sejv
	xpTZHaUPeNp9i0Oh4JpcmynC7bUjsPF3VIOlcg==
X-Received: by 2002:a05:7022:b94:b0:119:e569:f268 with SMTP id
 a92af1059eb24-1276acc04cdmr5060553c88.17.1771927820975; Tue, 24 Feb 2026
 02:10:20 -0800 (PST)
MIME-Version: 1.0
References: <20260223222226.work.188-kees@kernel.org>
In-Reply-To: <20260223222226.work.188-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Feb 2026 11:09:44 +0100
X-Gm-Features: AaiRm52EJS5rgTYBcMR4dvDDf9YsS_mzcf4b8zQ6Hta7CXM46-hJuj2wDErJbiQ
Message-ID: <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=m0Phm+Qe;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::122c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBEHS6XGAMGQEXXO35JI];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	HAS_REPLYTO(0.00)[elver@google.com];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 31FDF18525B
X-Rspamd-Action: no action

On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
>
> Instead of depending on the implicit case between a pointer to pointers
> and pointer to arrays, use the assigned variable type for the allocation
> type so they correctly match. Solves the following build error:
>
> ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> [-Wincompatible-pointer-types]
>   171 |         expect = kmalloc_obj(observed.lines);
>       |                ^
>
> Tested with:
>
> $ ./tools/testing/kunit/kunit.py run \
>         --kconfig_add CONFIG_DEBUG_KERNEL=y \
>         --kconfig_add CONFIG_KCSAN=y \
>         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
>         --arch=x86_64 --qemu_args '-smp 2' kcsan
>
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: <kasan-dev@googlegroups.com>
> ---
>  kernel/kcsan/kcsan_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 79e655ea4ca1..056fa859ad9a 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
>         if (!report_available())
>                 return false;
>
> -       expect = kmalloc_obj(observed.lines);
> +       expect = kmalloc_obj(*expect);

This is wrong. Instead of allocating 3x512 bytes it's now only
allocating 512 bytes, so we get OOB below with this change. 'expect'
is a pointer to a 3-dimensional array of 512-char arrays (matching
observed.lines).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOpXe7tCP7tyR04Hm%2Ba8zdiBWWQdK%3DUS-qTL31mm%2BYzkw%40mail.gmail.com.
