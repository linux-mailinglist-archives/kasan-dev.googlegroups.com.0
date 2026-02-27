Return-Path: <kasan-dev+bncBCMIZB7QWENRB5VWQ3GQMGQEBD3D2FQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4FgiDnmboWl8ugQAu9opvQ
	(envelope-from <kasan-dev+bncBCMIZB7QWENRB5VWQ3GQMGQEBD3D2FQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 14:26:17 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13a.google.com (mail-yx1-xb13a.google.com [IPv6:2607:f8b0:4864:20::b13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B56981B7A03
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 14:26:16 +0100 (CET)
Received: by mail-yx1-xb13a.google.com with SMTP id 956f58d0204a3-64cb719e778sf3634909d50.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 05:26:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772198775; cv=pass;
        d=google.com; s=arc-20240605;
        b=cwVhJ0XWsZMz2/QG++unWQ/yB11ihMs5S9IqKxQkpuvZtuu+5C/hLdpbgt2FRTJyfp
         TvcgExQccsrMz6S/mKW5Dg2WCOzd3yETKYZRffHKVz1dMpFKSkUN81RRpIgrMScUJzfe
         qcJuaV6jKl5wWnL9l5cNcStVcQh+rTZfcETaGOPoQfaMdOH5tP7PnSDM3NRz3XMR+Alu
         fWmnSLBMEVNMKhaAhSZIneD7b9dKr77NPw4DtdO+STYY+lnjYCkPhS0C693Kjh6cY6O/
         dydjF4LArh4oMLdlxvR970QdfVviGHl9w3xeqdgJeL0LOTlbkis1G98lmOCidE4s3cxg
         uXRg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DKM+tV8JCJTKvhoZWgKIXxbsc0eNvE9Gd+jnoinOxys=;
        fh=dITFrqqSObafTpP18cCwzhPpYE66CgCrYfI5CTO9XVY=;
        b=V0K133aIX2v2cIt7mORaf1JQh0heVGZnn4vIeQMIA8KZCS2l+2pZBx0GdJCD3UJ3ml
         l7w1tWA1w4nx5NRLfP2QjNUn6V0Ww4USdVofStsNQpgEp9NxCToY6MzTAy1jQKPkWFa0
         CEhdilocerJBoBZkVf5Vi4FoAEmPeWR+a19HCp3jSCqWDLlaOYX5HnT7WAHg4g2qja3q
         DNyDaaeragKG1WLIaK58yGzm9Bstx47eWnLu9lJvBtIEhsh5SzE5cGi7+aECE3SjGnrT
         h8HWxYOEeL5Xcl5jMUJdCyTzqwkxa8uxiOfFgR7TIkE1jhiU863zrN31AdZu2avpg6l2
         /FDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0sQ7iJkl;
       arc=pass (i=1);
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772198775; x=1772803575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DKM+tV8JCJTKvhoZWgKIXxbsc0eNvE9Gd+jnoinOxys=;
        b=wXI+Q43/48n542KEa1ZjSQGufFjk3u2t1wM3izM/tqCBgx7+YMyizV8r3gcZaakdVS
         osysmYv1gSRmCFrEXIm3zBQ10iscv2//ioIp/SIN1ZHiplNBFM8skeGaZg0a/59SIEcE
         pEWcD2hiLZMXCke/EBIdYTmBIrZ7EuCkqHTB1grGSnXmCAFnCJvR60xHs3RTIApobQ63
         Ht2D0TRhpVBn6ydVSWmW030o/yC1SX12Hx8J/HXqWPHzwGnd1x2rYYzooWCP2h0lFAix
         0TZnBkH60ju9WLUQKOIMc0fMXRod1Mra6Wc2u1y4pd0R+3I4gtzGlRPxkEiRm6QmV5F6
         rTrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772198775; x=1772803575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DKM+tV8JCJTKvhoZWgKIXxbsc0eNvE9Gd+jnoinOxys=;
        b=KT41De6DiJoWSftg6SYB2Lvf9Td/SbSGEFwefcOPHeAXQRZIM77eBdHGs4h5/KE3Tu
         r3xHDmlKbVSAq/Tu9HdAF7vXPJJr+A+E9C/i5uMhMe1fyRnPM8wg2LjYmsM2IPShvomt
         1RX68zsj+2DVvOAz2YZfPbX53fYQY0rhIlC9WF8gPjrEaFC/UKAzRb/xFxoHCrbAQ6r/
         Cek9tJ/vqZgM1NOWSlYlgbOk1m1WT8jO77wS4wc38Z4IQXQkcYe7OpePtUcArjdLzBkz
         t17GBh8Ftup0V3SRBWZSj1CooFsw3C3q/sEN8A0VgzwbD1eo+6Gu3Eo94RaNbHimcVZg
         +h6Q==
X-Forwarded-Encrypted: i=3; AJvYcCWUSWQvxSNqcMXTwgyjcRgtRwQYfwHc0SghgwTQWR5WW7H9786y7ECzbZ9nC0ek+XxWROR8Lw==@lfdr.de
X-Gm-Message-State: AOJu0YxtZHVjQhOE6M5e359FwhRA0TRhy44Wv8t7Ncg4BvXSmSrTuRi7
	nutoy7w9zhBYyGK2UZJsu3AQHWUgkXyRilnsc3IkANbG00yVoOSYWMW/
X-Received: by 2002:a53:a04d:0:b0:64a:ee9d:8b7c with SMTP id 956f58d0204a3-64cc2225811mr1667900d50.42.1772198775167;
        Fri, 27 Feb 2026 05:26:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ELuRp06/BgV8zwZYZRF8FKUzecOTof+ZeWW9CD3P3DrA=="
Received: by 2002:a05:690e:12:b0:644:711f:4a0a with SMTP id
 956f58d0204a3-64caa9835a6ls2758575d50.1.-pod-prod-09-us; Fri, 27 Feb 2026
 05:26:13 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUYf/6yA/2ORBBeaNPbgAOxlEKZGFlAbfFM3a6pMvrPcOevF5jVffRpf+oA+qXeKxjJtfbcv6yxF6k=@googlegroups.com
X-Received: by 2002:a05:690c:3607:b0:794:7210:61dc with SMTP id 00721157ae682-79885610aecmr24242567b3.66.1772198773213;
        Fri, 27 Feb 2026 05:26:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772198773; cv=pass;
        d=google.com; s=arc-20240605;
        b=BfMtProsMIOfONAF00CMijOV6VxuWk7ji3c20owCNDgelN/oUr4yqd7ak8WxDVrN4+
         qfRZdrvWQ5DnqSBKhtWk7DbnklMig68fQUKBXDZWRcrUYZQh5xGGHK9M4JzI47br4AXx
         2+lRWNWTzz0ms+yKsrt4uP6etfqU5ySot4EBVA926DqF0IbHRCmJDKxNTPn8eA88cpAW
         8jQbGDUEIl8cKpWS8ScXdwTbDBAA9SmdaH27d+jq3ixdIRyuoSW1cj2Lv+FvjNKEyJLJ
         JaRQrI1DQ5yFv7Y0COcEcLzLmr4QRFft8zZhCnue7z+Z7GoOOzMfAxUaR9yq5XDl8dqj
         Bsxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mfk4Li2b1DY9WeZ7TXgh8JQ/TGajjPvOz3xaLQNJZoo=;
        fh=Oc2ZkngVc9lgy+5zcqq5R6k4eYUzuQJFoxPOUvuJq+U=;
        b=RaDnw56j4+uuap7SQdh/UWpIDIwf3KjIfbPRbl+i9JixnL8uAGtWTe4S5zilXwU7S7
         aJD3d2WMCS//uFydoqaPULLol4fbRhN7gKFrHRrRbFNHZBRsjBzw3fOR1bX2rWo224Fw
         ftyRlxxfYJHjYpJNUTKpwA0cXt2oH4jMX2kVfpwWvmO39X5a/eWcvcMVDgKi+fj7jSnj
         DhuPjNiW+d/wO7qxYjy85ljbdPB0NwK/Dg0+h931HeNSu3UG+6/dLNsRgyWTfONqEjcU
         3hZS4lAJ8PXuwNFJg4eSN5g0BSJDsob2pgL2RjLsqYqoMfwzQtbphZTWEaLbY5lGzAtg
         gFyg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0sQ7iJkl;
       arc=pass (i=1);
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-798768e79d7si1684657b3.0.2026.02.27.05.26.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Feb 2026 05:26:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id 5614622812f47-464bc03efd8so727842b6e.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Feb 2026 05:26:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772198773; cv=none;
        d=google.com; s=arc-20240605;
        b=huN7pKVX/tptZbnKdIH08VsuLQZ8TO1qBTjG60XiNNnsKmFzasGZZtO6kl78iPDBH8
         +SJwRmFiXJbqupICCEmJprmS2sdR0XRSFfFtaRBJz1JFyjlsf0eQSmsYxRYeV0a4MErF
         rpI6uIG5BWXY+7SvkaGMue6UjkfndIn6E9EIw/0r7E883fmjormQI9BfpQAhr2EZ5OOC
         RR9RWn5PW9VBbtkVF34uU2LTMWGF3wBkbYAz+ljo2IzO9k1tSXMKJUBHpi5DKrAjBkGQ
         ZrZ+wDcYbnDjnY/HzxD7EKPdyg/w4Wg2hNFI2dzRYrFwx65NE9qlm6vTvY0SlLKAN16P
         OzdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mfk4Li2b1DY9WeZ7TXgh8JQ/TGajjPvOz3xaLQNJZoo=;
        fh=Oc2ZkngVc9lgy+5zcqq5R6k4eYUzuQJFoxPOUvuJq+U=;
        b=Y+Hr/bps+sIKRikfBeDQsu9E3Py3qV7L/EMed4oeAEA6hE/yk3SamvBHvM+I/xZ2i3
         OK1k+lJ9jAirANCciGT+W+PGCOobEZL27eb5t5DPP9VJfXiuaTqABpKVyoMX03vsyYow
         7AXSwwZArhGvUx9JIxK2MK9fMHT1ZEbvRPXAfyWFwfXb4BeCUebIuFvlxbtNakURDrRv
         hubrcJ2PDqia/9Unpqafxipg3RvpLvY+KGOg3z7rfzOWgHm9dZhylPx09+ibrOKtjMng
         KSjhGaIuDM4ZsrttSWt4tR7nUzl1DCJo/W5iXAOXbS7pB7qGSzkxOLYIY7YQplH/GGtC
         8FDA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXE+FYP7uzVuyfmH/xD5kSq0sKzgZq5ze6qem1OMwJB5fAbCIJ8HnQzQUMIQdHpo7qgMOOZw6lK+kg=@googlegroups.com
X-Gm-Gg: ATEYQzwzIWBpAiFAMEWX87ga6JysCO0GCnU8ijiHIQEJEiPrNNb6WnxYm2jE7/MxomM
	g+d24A8y1JhAZ4Io8WxLhfFBfzsUOc1ru5SZyc3a3FyjQyJgJquMwMzEO0UJVQnYDxeSCQkDg68
	wm8lT6RVL3hcflhuwV3ygI2+d0eYj2rdjya8bQ2vTJ51Hii9sDFQ/rU4YYAFBi+rbOGLC3M+KP1
	X50FYLvj4oAQ2szTj/Qs1itDtYdAP+re4dJ1bAyiBnNsXFb3HG4uKPxXr/dukngD4nG4S5WdK6f
	dRQLC9goLNL/xWCYq9C/cvihWLem0R+H1aOxekAaUPRXmzL8l48=
X-Received: by 2002:a05:6820:228a:b0:662:b892:40c1 with SMTP id
 006d021491bc7-679faf40534mr1561644eaf.52.1772198772372; Fri, 27 Feb 2026
 05:26:12 -0800 (PST)
MIME-Version: 1.0
References: <20260216173716.2279847-1-nogikh@google.com>
In-Reply-To: <20260216173716.2279847-1-nogikh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Feb 2026 14:25:57 +0100
X-Gm-Features: AaiRm51FS4k8kOf7uO0kbvfFeX0fSClNoyJTiSSMW0qBp2UPnW3a0tFMNsaTgRQ
Message-ID: <CACT4Y+b1UZpV_i68cSP3XOBsr9EfbX+SAbXRdL3btmAnSvmMBA@mail.gmail.com>
Subject: Re: [PATCH] x86/kexec: Disable KCOV instrumentation after load_segments()
To: Aleksandr Nogikh <nogikh@google.com>
Cc: tglx@kernel.org, mingo@redhat.com, bp@alien8.de, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0sQ7iJkl;       arc=pass
 (i=1);       spf=pass (google.com: domain of dvyukov@google.com designates
 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCMIZB7QWENRB5VWQ3GQMGQEBD3D2FQ];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[dvyukov@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[8];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid]
X-Rspamd-Queue-Id: B56981B7A03
X-Rspamd-Action: no action

On Mon, 16 Feb 2026 at 18:37, Aleksandr Nogikh <nogikh@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  arch/x86/kernel/Makefile | 4 ++++
>  arch/x86/mm/Makefile     | 4 ++++
>  2 files changed, 8 insertions(+)
>
> diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
> index e9aeeeafad173..5703fa6027866 100644
> --- a/arch/x86/kernel/Makefile
> +++ b/arch/x86/kernel/Makefile
> @@ -43,6 +43,10 @@ KCOV_INSTRUMENT_dumpstack_$(BITS).o                  := n
>  KCOV_INSTRUMENT_unwind_orc.o                           := n
>  KCOV_INSTRUMENT_unwind_frame.o                         := n
>  KCOV_INSTRUMENT_unwind_guess.o                         := n
> +# When a kexec kernel is loaded, calling load_segments() breaks all
> +# subsequent KCOV instrumentation until new kernel takes control.
> +# Keep KCOV instrumentation disabled to prevent kernel crashes.
> +KCOV_INSTRUMENT_machine_kexec_64.o                     := n
>
>  CFLAGS_head32.o := -fno-stack-protector
>  CFLAGS_head64.o := -fno-stack-protector
> diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
> index 5b9908f13dcfd..a678a38a40266 100644
> --- a/arch/x86/mm/Makefile
> +++ b/arch/x86/mm/Makefile
> @@ -4,6 +4,10 @@ KCOV_INSTRUMENT_tlb.o                  := n
>  KCOV_INSTRUMENT_mem_encrypt.o          := n
>  KCOV_INSTRUMENT_mem_encrypt_amd.o      := n
>  KCOV_INSTRUMENT_pgprot.o               := n
> +# When a kexec kernel is loaded, calling load_segments() breaks all
> +# subsequent KCOV instrumentation until new kernel takes control.
> +# Keep KCOV instrumentation disabled to prevent kernel crashes.
> +KCOV_INSTRUMENT_physaddr.o             := n
>
>  KASAN_SANITIZE_mem_encrypt.o           := n
>  KASAN_SANITIZE_mem_encrypt_amd.o       := n
> --
> 2.53.0.273.g2a3d683680-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb1UZpV_i68cSP3XOBsr9EfbX%2BSAbXRdL3btmAnSvmMBA%40mail.gmail.com.
