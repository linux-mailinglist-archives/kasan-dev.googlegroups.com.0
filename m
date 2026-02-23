Return-Path: <kasan-dev+bncBCXKTJ63SAARBR4W6HGAMGQE2SQRC6Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KIeEA0tLnGmODAQAu9opvQ
	(envelope-from <kasan-dev+bncBCXKTJ63SAARBR4W6HGAMGQE2SQRC6Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 13:42:51 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 89BA717652D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 13:42:50 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2aad6045810sf44220825ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 04:42:50 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771850568; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqABTT6bThODeXWPrPieMPPA965TmQRmnh6SNqQ/+4u93cZttx6NZzNvhsPN3G64ic
         BUwFgyWk7yj3KOw+Gccy04Q1Ge510mjBoevDZp7G3J9OhyMauwq5MZnsDjInWvld993g
         9JU+JJUprT28TACwJ7h8uVzUN0mWMGxtIghQqYLYEN33Lfc9J0TKj5SNMUkC65N3lEre
         2wwGaX0a5J4EZJePpvy/8ZL8xAFJ92fStEgHjHl6+yteDn5U79RQNGhOsEo/xMmZIcXC
         Rhln1Hxcn9Op92VTkiMeCAEZQVSC1VaS51RCYIKvHSEa3J72n7AEtKDyd286OV/mKMlD
         iL+A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Rq9BeWfQd0ztsmBCiJroUDYrHjMDWbPNBnsxAXmSi5k=;
        fh=sagKWStbgo58EW39NXLLLEA1qZlbvQJ0eTqJNeym5Ag=;
        b=Y5yewTXcuZGVzL0GbW71qO7g88hujCKFK0zBzI8Kmx8jTK0IP+fQmohaZ4aN9Dtatb
         bXFToB/tEouu29InWYSObewiBET1B58O2D0vbZ60XkmvrjT7rCQeGYIafyHnhlNOYJpz
         0XKE75Zsa84b2o8hsiLdxwhvO/cTRu2tAFgyAlXvzjMUnUA1g5YCel8DoiNchbuxLzYD
         5PD+OL2W14k7aBvjKIZioR286zQEWWA0fDgGp4yoMZklqsgP3tP31jKHtTtlXAYW80RZ
         ClvNfJC0BXykk5PQUVtAI+X9CtVa+WzDYB2Yof9cZEmTmLoYJahoqfrwycNCHIkETZgy
         wH8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UeiY3oFf;
       arc=pass (i=1);
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771850568; x=1772455368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rq9BeWfQd0ztsmBCiJroUDYrHjMDWbPNBnsxAXmSi5k=;
        b=CKOaQPLl8OrSCzHK0lCW0pQJDzfnGA/cyZ2Sw2sRLBgDbNkWo60zLZYYu6A7f8kYMU
         hVNcnI3McVdYYAuYDp4JyKykqpSeL3X9UcI8eLP7p/K/KPZDwvMb3uIn9RCD/lobqF1k
         DoCGcVMS/W95KQnfykyhyN2xZNq8lkHuZnT0ADUuvp7Cj1tf2dUpP3g5OrkcHkT2d3os
         EriFmOu+Rj/mTA7ZP8blefVf9t8ijFYtdYC60YIvcChuZ16TRzYlB0fJF8Nun/SGzcaR
         SUEU9awgWcUZOzBiBEPVQfwCALD6sO0q21MQMYK8IAj6BkgBwx4GRZpmMOtNA5s2Nd+V
         GsLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771850568; x=1772455368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Rq9BeWfQd0ztsmBCiJroUDYrHjMDWbPNBnsxAXmSi5k=;
        b=FKo+Ir5rGfqKS7uQU9HAC1C7fGSciFT5rNbkI+SE2rX0IGi04hYoDTKkLu6C/3mbnJ
         HyNRtouUevPbDdDUktIdYpBqY27ch5jbmoUztRAXinvGVwoCN09O5m0/wNm/Oo7G10nv
         75ONZ+O49BGJ1yem22mKh8oV6xZf9kcez5LKBip8KVj98yopE2qKOjFC+x8UEKeZfhvA
         u7SynxRgEc+o+zHeLAW6Tj3aPsBotWdFagL2v/FiCCWvqIUWtcIDo4LaxYFiKtBz7QzJ
         wH+mx5QpxSq9tee+Oh33upSp8VzGFiVB7+0YNswO75hCHDtmCd1gVRER2UMaWvSvdVyu
         2+ug==
X-Forwarded-Encrypted: i=3; AJvYcCU05QEwBZrsazzLs4dCyZeBkLIW9TKbViO++PkpZ1uW7NmPQxwJFIRRpZMSrTioQbKJ0QI2AA==@lfdr.de
X-Gm-Message-State: AOJu0Yx4H2x2HFWYXMJxWUiJj6G6qGDbxBZhMW1vzedE1QfJcrJvOJjz
	v+ZFhlsSmCRauydHbNm1oCjlajDEfTOuDgZbCbWhDTAAwzG17vVK0Ri1
X-Received: by 2002:a17:903:2c05:b0:2a7:d5c0:c661 with SMTP id d9443c01a7336-2ad7443a1c0mr74591095ad.15.1771850568220;
        Mon, 23 Feb 2026 04:42:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FgBGBqQR5eKPQ+XSMwf8W3E0HISz9fF/rnsewrt1UWmQ=="
Received: by 2002:a17:902:7b8b:b0:2ab:2303:c0df with SMTP id
 d9443c01a7336-2ab3c1b3b0als89570695ad.1.-pod-prod-07-us; Mon, 23 Feb 2026
 04:42:47 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXA2R5Lcx1KglsJZuudDriV4zfNP7JJ33PBAuGymXd9+IOceld3wCgr+XklzWfT3A+pgW1LGcqQ/FY=@googlegroups.com
X-Received: by 2002:a17:903:41ce:b0:2a0:9eed:5182 with SMTP id d9443c01a7336-2ad74449c1emr66097555ad.20.1771850566697;
        Mon, 23 Feb 2026 04:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771850566; cv=pass;
        d=google.com; s=arc-20240605;
        b=RX1SXo4z0ZjZ8yrP4NjmouUZBYrH3zHjy0h0CkqZ1z9YZzH5X1tdRSBDC5InukuftI
         kw9OgKVEsl81Nhc0lr5tynyp2LatN0sPUFc6aWMKuhfKkUW2tYbtF06XsQ47dQVv6IUL
         9AYpwIfMPbci10x3iMtN6LU5jW0qfr9kuy6HJlBM5YqZC/gC0mu5p+6j4id3MWv69o9d
         Nblj5fSB9HizpVhbhJxOYdDBo8au69LT2yGkV7oJREh1MXYr6J81hEHnujS6ums1ff2o
         +QZ8376BNAZPb316K2i5kUa2fA1w0TZn1J6KDJPLX20c2qAUcvOUo76OE54q+aoV/jGZ
         VO2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QwHlGbS3cn9jSgHE96pfHR85LcmhKeNoxRR0LDuTZE8=;
        fh=dz5x/TF77eC9XiL5bG6ytBJKtMHVgbxFVccjLY0EH7Q=;
        b=R3TulN2njNbZHfcQ4vbVGdLW40YHZ2PBD0nzV6qQkpsWk9xsv70bDoWOuijzaJS6K8
         oYfEmHN99aPt0qI0ugQcm0nhTLKjlT+PuULPiE7pR08UJ3hlOraHRKx3scGsH0ABAGMT
         wzRYSNjKzW4a3UBUgSpifWOzd5tNhpGU0g99JJTa2zAcU7zAt+ApeMdbQ1mLVpkhCxrW
         C7IWE6fWI3EI+VvXaD6tkU5DspHiOuRBNhQ0um+AuiIqdFb0T7aVzRwQA5V3vUFJYl4v
         BkL73qDxVZUJmWtUtl2MJjbvFwxVUV14ix0mGdCL1xn/ZwHW3Htm4zQuLFzkkMt54Gho
         SD3g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UeiY3oFf;
       arc=pass (i=1);
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ad74e17e07si2583935ad.2.2026.02.23.04.42.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Feb 2026 04:42:46 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id 46e09a7af769-7d19bfe1190so3609089a34.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Feb 2026 04:42:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771850566; cv=none;
        d=google.com; s=arc-20240605;
        b=YLjChCJifQ5Dh1o1jYH8FuOi6qzgSdMzt7KKUzzwZ76YnctafRP5nMCwASamKdxq7F
         p6g4vbgxkkiZmJlX7CgYBTNfBShyJevyaOYa3io+JR6RMQ+ENMnljAYpl2bUXf8HRQ3B
         Ae9CGGd6yoZzp26iKGJj4CPNNxofl7teiDmIKsuxn40sgHo0+bZnDiyUnKyXwD1dqora
         OdQoPChOup9oUaawGkGQRQtE5xW4zW9sYN/XMy10H60GFGfkHjaZvpmyJ27R9byB9rhK
         oPW8yfW9/gcTFD7LUBFpjaZBaDcPHWGG9XhxDG4JmhCitvmLGTazL0FzJdrWfovh03M+
         fEvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QwHlGbS3cn9jSgHE96pfHR85LcmhKeNoxRR0LDuTZE8=;
        fh=dz5x/TF77eC9XiL5bG6ytBJKtMHVgbxFVccjLY0EH7Q=;
        b=TMCealkqxo0PKWtyZ+lCfNjoIl7+7+DOlTcCZHQY2/PKp9b/Z0wjwEDaljRchoC41x
         a8rxO51oJrVR7/PnIfWHgtHcVDxGXgT/t1x74Ojnhki5V3J1HHG5A5ZeT0orzu6zLuln
         MGMMq0jeD8Py0+XmDhLwQeiSpfTnyTvDGZqhQ0jAOXohjZUieUgLcSpEpw7i+QLpr9oZ
         CcP5e9bsCEO4AlFuyRhYMW4o7zqi9pwUNryQnB+8pvLKcNWZVj1Keo9fA+wOdsgwNsne
         IzYkiLpitZINvgfLCzW3V1cV+3PCEXVEfupo8L3VurCQAB/2PcduEhpnGy30dv1eYTjZ
         FQJw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVtaLpFSD+uWJ1lFJ8dw7ys1aRWP5giyXpGWy6DUMgODYueI4yIc+3P8x/0Tv1WWRjMQnExyyFTa0E=@googlegroups.com
X-Gm-Gg: AZuq6aJtocckJ69L84S9f5qMeNFWxxJ/etu9XWScc2+SYujTASDX/69shzE7vOXwmon
	mIo5CVz3X5ewnInsvNeyVFYXeYjliQAEFrd/dLBM8bByXyNw/2yz8NSpgN0u0xQ8uzz7wqOl9BR
	/9vzaN8L38StBEdH+8yn8alUIxaccSfwxdqGXFzT9RVcPWmTSNJGDKmInkM2ivWtOy1082ihaFw
	gF2+7SK1rwj7h/8lDr8irn4VxAGpMdeakAnxi3hqi3QNqJQLM6FfSOgd7AnNaHEoOPmWvTz7y3v
	MoeN/f2ABkP81KriTUJZHYeMniSN2uBu5Wy1ZWl7AmEhGSEDXzNCX2T6mXuVxlZZe6p57LRnXiT
	rEISU
X-Received: by 2002:a05:6820:4410:b0:678:7266:8e9d with SMTP id
 006d021491bc7-679c46115b0mr3809769eaf.76.1771850565555; Mon, 23 Feb 2026
 04:42:45 -0800 (PST)
MIME-Version: 1.0
References: <20260216173716.2279847-1-nogikh@google.com>
In-Reply-To: <20260216173716.2279847-1-nogikh@google.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Feb 2026 13:42:33 +0100
X-Gm-Features: AaiRm53XIB_8hrdBUvZtKbbzwwdkFXPuotzr2k9FukKdKsESIA-40mClL6YShhs
Message-ID: <CANp29Y57fyE4H=FZju_AhBkzfeKBPXJKDEumqBKaR+zxKwMYbg@mail.gmail.com>
Subject: Re: [PATCH] x86/kexec: Disable KCOV instrumentation after load_segments()
To: tglx@kernel.org, mingo@redhat.com, bp@alien8.de
Cc: x86@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, stable@vger.kernel.org, 
	syzkaller <syzkaller@googlegroups.com>, linux-mm <linux-mm@kvack.org>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UeiY3oFf;       arc=pass
 (i=1);       spf=pass (google.com: domain of nogikh@google.com designates
 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBCXKTJ63SAARBR4W6HGAMGQE2SQRC6Y];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[nogikh@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[11];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 89BA717652D
X-Rspamd-Action: no action

On Mon, Feb 16, 2026 at 6:37=E2=80=AFPM Aleksandr Nogikh <nogikh@google.com=
> wrote:
>
> The load_segments() function changes segment registers, invalidating
> GS base (which KCOV relies on for per-cpu data). When CONFIG_KCOV is
> enabled, any subsequent instrumented C code call (e.g.
> native_gdt_invalidate()) begins crashing the kernel in an
> endless loop.
>
> To reproduce the problem, it's sufficient to do kexec on a
> KCOV-instrumented kernel:
> $ kexec -l /boot/otherKernel
> $ kexec -e
>
> (additional problems arise when the kernel is booting into a crash
> kernel)
>
> Disabling instrumentation for the individual functions would be too
> fragile, so let's fix the bug by disabling KCOV instrumentation for
> the whole machine_kexec_64.c and physaddr.c.
>
> The problem is not relevant for 32 bit kernels as CONFIG_KCOV is not
> supported there.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> Cc: stable@vger.kernel.org
> ---
>  arch/x86/kernel/Makefile | 4 ++++
>  arch/x86/mm/Makefile     | 4 ++++
>  2 files changed, 8 insertions(+)

A gentle ping on this patch.

Should it go through the x86 tree or the mm tree like other kcov patches?

>
> diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
> index e9aeeeafad173..5703fa6027866 100644
> --- a/arch/x86/kernel/Makefile
> +++ b/arch/x86/kernel/Makefile
> @@ -43,6 +43,10 @@ KCOV_INSTRUMENT_dumpstack_$(BITS).o                  :=
=3D n
>  KCOV_INSTRUMENT_unwind_orc.o                           :=3D n
>  KCOV_INSTRUMENT_unwind_frame.o                         :=3D n
>  KCOV_INSTRUMENT_unwind_guess.o                         :=3D n
> +# When a kexec kernel is loaded, calling load_segments() breaks all
> +# subsequent KCOV instrumentation until new kernel takes control.
> +# Keep KCOV instrumentation disabled to prevent kernel crashes.
> +KCOV_INSTRUMENT_machine_kexec_64.o                     :=3D n
>
>  CFLAGS_head32.o :=3D -fno-stack-protector
>  CFLAGS_head64.o :=3D -fno-stack-protector
> diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
> index 5b9908f13dcfd..a678a38a40266 100644
> --- a/arch/x86/mm/Makefile
> +++ b/arch/x86/mm/Makefile
> @@ -4,6 +4,10 @@ KCOV_INSTRUMENT_tlb.o                  :=3D n
>  KCOV_INSTRUMENT_mem_encrypt.o          :=3D n
>  KCOV_INSTRUMENT_mem_encrypt_amd.o      :=3D n
>  KCOV_INSTRUMENT_pgprot.o               :=3D n
> +# When a kexec kernel is loaded, calling load_segments() breaks all
> +# subsequent KCOV instrumentation until new kernel takes control.
> +# Keep KCOV instrumentation disabled to prevent kernel crashes.
> +KCOV_INSTRUMENT_physaddr.o             :=3D n
>
>  KASAN_SANITIZE_mem_encrypt.o           :=3D n
>  KASAN_SANITIZE_mem_encrypt_amd.o       :=3D n
> --
> 2.53.0.273.g2a3d683680-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANp29Y57fyE4H%3DFZju_AhBkzfeKBPXJKDEumqBKaR%2BzxKwMYbg%40mail.gmail.com.
