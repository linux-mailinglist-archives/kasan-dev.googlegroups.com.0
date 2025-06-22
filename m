Return-Path: <kasan-dev+bncBDAOJ6534YNBBBNK4HBAMGQEU3QQ5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 17290AE31A2
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 21:09:59 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-606e35c3627sf2689211a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 12:09:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750619398; cv=pass;
        d=google.com; s=arc-20240605;
        b=K7wELXJzMBPGPCWEDTwjd50GJMFQTuk9Y4cG+zQ/LnM0zecLxFs07f56J5F2KdnrdW
         pEzOpNafi4S4VgZptM077UZwTVdRBukacyQ7jJyfBoyfGmMDQjhMG1CUPBtg3MXu1udK
         DI0DOx5rmIa+2Kur/F1geqkd5yC8YFsZNhjyDmcvOPWAkBKLXLXkWHJ5Y6eyBJs38Ndp
         yZCg2kKaVkp7NYmic4CUN+Z/2j8LQ/GscwSI7WkgK6GwEO+C+s6PBWnkLup4jMXpv7PL
         ux0UwvdwMIS3MgdaRFlYMCuCab4QY3DQj2xtST7I4Kenq/IK/7eVc9rwKTVZly70M12s
         zIgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=rFG+7cakSR4hzft/Bb6QsmesHsLjCmkY1YhXGeMgm0s=;
        fh=wUBShZYybSWttQ0leV5D/0iRnZ20rzAhLTIpOCHxJZI=;
        b=e6ixTUxG9GTN8fxifKt+YctnadCp3aPBYumIiieNjOykh/ffo8g+fdj3viLY/wX+nm
         +16+OaEPJLZ3jaPOzhC16p0WJS5l9qio61wruBieGAFB8i9pT1o9+ZVF6DeS3FbAk5Kx
         FCzznYmVVFXNiPYMuRQ1KyuDCMLpYeshgkU/R24Xpqais6oEWq9jhQJU5h+U9s4x90ka
         25LxjScyBTgw/569oNhugVOaykISLbsI5jCAU6+9674cbxYwhE4r2KMKAL2eZy2ZNpFE
         jNQNqdGf1WaAxz2bWKHiQpDG3er1NH77kS9WTZ04WE/VKG2kkfvJshHjGhhU+jHoHw6X
         Dd6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LVYtLJY1;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750619398; x=1751224198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rFG+7cakSR4hzft/Bb6QsmesHsLjCmkY1YhXGeMgm0s=;
        b=QWhfFxvqr7Q8b1/0WuH1PMgSMxhyie9E2DNvU2aDWjVok5UR9WGL41ZdthvwG3I+14
         tOkeTVZe7fxdWZsEvQS7dOKQVSKGxmRbs2fwhzw/2EX9FEjiBGg5jVvEVwLeAU/UJrGm
         d3e546n6jcb3dJXhZgqaSUOu2IQuQH5rpa1Ai/+1RcXnwgUarzG2bJLSIRZpN9efW+2E
         nJXcd9Rns+FuIwJG22nQh2ZcrpFm7POqy7nMguT8eNbdNq97NGgTWvy4aDAOka4c7urj
         T7jBVXS5ezeAaufGcGW6IfV5Xpi+yIwJMJXkaYlBRXDgb8adeeZOVTV/eSzLnCZ28jnR
         LmGQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750619398; x=1751224198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rFG+7cakSR4hzft/Bb6QsmesHsLjCmkY1YhXGeMgm0s=;
        b=b8/G2/t3tij76ZAk43+qGk+qBTJ22HfjcGUCDe5nJmWeuGjpOyvA8ZP2If0dEIUqPe
         klNVXeVEqJlpia3i5wo4eMjag2UHzlMcIfkKMwx43L2JOmYqnbkL/9KJIE93ydSrPi2O
         e6RFy4OwR01V7oT1ri/t1YMaFZ8+Cnw6As4NFR24XwMKLU91RAkv1QrnxnN3s2eCshc9
         CJb9UmClWrugYOlhfDRtvaXZmCKB/TCQLIf00f1SAsHsUyj5ddDcafXRC4HE5zAOsVnE
         M9Z8RBbcnuTcbweIVZ1o5UxyBXMKFVQ+dWyX8pnP6qWYoxc/Hkz6Va0hvcQVEgngQqW0
         S1qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750619398; x=1751224198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rFG+7cakSR4hzft/Bb6QsmesHsLjCmkY1YhXGeMgm0s=;
        b=tjpTP4DgA3zDiE9oFILnoIxAvANhz8riWOgx/RUrF+0QFw4NGgNh9S8IhmD4HxS0bp
         Z8JWKKv7fVmwsSNP9KZCRDQzQhZMExBWXvR3Qzi43E8YuSjpIYre/ELLaq8OFIxxE/ZA
         ffMe9U33Tdc1z/7VH2RirXPeX+Q6HgOTdbrlCqgMnASnqJfIhwapkBzit1B47AH+bjBS
         BDC5LqYM6Mu0N1NRkjbSc34/wQ+3vPWQFcj9Mhwgk+XIlMPKnwWp8k3Sa+FRKJwe44zh
         /UDloFY43glQ21oveEqTsbN27SJ/aOI3G1tUFZ1Wlvup4QGKJS7N2gGKbokE0s+5IsmJ
         3ZnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXP1vVSVa/BVJ9OXJwRTh8gjujQGy0XF3yxd5xKZPUTbtilYZrmSc3GkDax1irVrsQMG+XJEA==@lfdr.de
X-Gm-Message-State: AOJu0Yx4bNv4mNkNJ/NiUxw/DAG+SzrSmux+YJlrGpqVX2UfFpWDNUB8
	ESv4QQfuP5744VbTM7vEvJaKBho6owr/znAlWWAQc/dLf4acPvHaRV9j
X-Google-Smtp-Source: AGHT+IF2RfFknobcS8EydZgZMyOsIefkAsuZvmMH1h6pvkCwdARHOD7HWTJiJ6b0dNUDaV+mkYFVCQ==
X-Received: by 2002:aa7:cf10:0:b0:602:1216:fdde with SMTP id 4fb4d7f45d1cf-60a1cf2fd8dmr8131917a12.14.1750619398077;
        Sun, 22 Jun 2025 12:09:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhQo/a7LxPKojbQox2DVj2yaZD771ltKom7dO6ni690A==
Received: by 2002:a05:6402:3488:b0:601:6090:4177 with SMTP id
 4fb4d7f45d1cf-609e78e25c1ls2504810a12.2.-pod-prod-02-eu; Sun, 22 Jun 2025
 12:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRp5So+SCEyRAg2uZLBkl01TkbGGwEUsUdppg5xS6eYbfymVMlZuEOU8ZUK+LYh5Hs4sFrx7n5miI=@googlegroups.com
X-Received: by 2002:a05:6402:350f:b0:607:f082:583a with SMTP id 4fb4d7f45d1cf-60a1d187fa0mr8498465a12.27.1750619395485;
        Sun, 22 Jun 2025 12:09:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750619395; cv=none;
        d=google.com; s=arc-20240605;
        b=gjVhOfQ/oAw9emkaIDmOLXTLLzEQLmHS9Q1I0/CLhnHMWMfTJQsKmm6rK1fU6CE0Zu
         HhQat73CcOL3U2axHjB6tNYjmAGz24ZHfdexTVaBs0qNxTuX92DL/6lTVI5PUIKxKp1f
         XyFl6aZJtn3EIq66vr1GsmYaxc65fLKDSM9Vq9EcW5hKuv5TNh5kcsNrVLmW+dDtrayc
         8JhdSaKcW0CkMRVN5uT2aKwTJ3OipX0UfRc69e6qjiMPBv8ZaVowoJ9xKlEr8R5xQyVQ
         S7ZOiz3Uo97kXuRueiZnPKLI+ffa2w+7I0cOoZtL5cyNlwofCuaO2P3sncq2r8GWmufx
         QQyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fPvPC3ewg8btyqEAcdiY9R7W/ks7YLMYkN0QU2bR+1Y=;
        fh=1IQjziZ1mP1J+YHFYFUc2c9HV2Vapt37HwS4lT4ieVo=;
        b=f6/M6La4SXCcAHpIJvIpE4TPEDLmjPDtLV6GPY62dZ9YV7pu69wdJiK+yXVBS/Pd1M
         e/GtX0q30GVNd3VBv+v3G+sxShVH61m3xtIZQkaZXFwn8mvoySc8tP4h+9Jsjrqk17pt
         2yLcd8ovcJ01HaF4zHstjcEGTiYUT5sTrQ34H3OOfTbZ+rSDOb8JIrRKG6XdufZ5X47S
         UBfFkBwrxj2LfURmAQMW0O6G0NJBiG73Ff3Zk3x/3hoOEB7ZqZZwZsrYWCNt22sY0gpl
         2iT4S939yfp1ik/f4zK9iWXDzxYWZox+uFlEdPZ2FvgCIE41++w/S8dZzlsDNRAgOI8q
         DUrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LVYtLJY1;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60a182ff7absi160216a12.1.2025.06.22.12.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 12:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-32ca160b4bcso9174641fa.3
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 12:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUA59BXDx9CR/BreH46mPV7VZDXcm4bgPPsCsVJLvzrTQxok16CTmeVuGQSRucJdBD+IsUpx0v+jpo=@googlegroups.com
X-Gm-Gg: ASbGncvSrEelnRJrkBadg/xat35q2+oiWT0ONJiU2nN4Ty034IswkGus8HbDSAN9K41
	y4u4fvHA4htGhcDGbsvNSjP6bsKGInQ8ny/0238QXh4m3vyFKz9vMNYeJ6dlWdRFkDzFcOmuU7p
	Qf4eXv4oa2HPYO3ro+1nA94GWz4NlFg2RWO8o4Vgh9eg==
X-Received: by 2002:a2e:a375:0:b0:32a:77a3:877f with SMTP id
 38308e7fff4ca-32b98e07923mr22842501fa.2.1750619394440; Sun, 22 Jun 2025
 12:09:54 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
 <20250622141142.79332-1-snovitoll@gmail.com> <20250622112014.76bdd8929ecdb1c1fb3015b5@linux-foundation.org>
In-Reply-To: <20250622112014.76bdd8929ecdb1c1fb3015b5@linux-foundation.org>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Mon, 23 Jun 2025 00:09:37 +0500
X-Gm-Features: AX0GCFt_VnjkwnxlecvFFQmeMV04Nl7ypc_hhjKQR8oRDBApGtCmD_ujn1PLyAI
Message-ID: <CACzwLxgSBszyEr4zRqMbnoA0PEnZQNy8_ZKTMtwm-Nkho5MePg@mail.gmail.com>
Subject: Re: [PATCH v2] mm: unexport globally copy_to_kernel_nofault
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andreyknvl@gmail.com, arnd@arndb.de, david@redhat.com, dvyukov@google.com, 
	elver@google.com, glider@google.com, hch@infradead.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LVYtLJY1;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Jun 22, 2025 at 11:20=E2=80=AFPM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Sun, 22 Jun 2025 19:11:42 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.=
com> wrote:
>
> > `copy_to_kernel_nofault()` is an internal helper which should not be
> > visible to loadable modules =E2=80=93 exporting it would give exploit c=
ode a
> > cheap oracle to probe kernel addresses.  Instead, keep the helper
> > un-exported and compile the kunit case that exercises it only when
> > `mm/kasan/kasan_test.o` is linked into vmlinux.
>
> The recent 707f853d7fa3 ("module: Provide
> EXPORT_SYMBOL_GPL_FOR_MODULES() helper") quietly added a thing which
> might be useful here.  As far as I understand it, this will permit us
> to export copy_to_kernel_nofault to kasan_test_c.o and to nothing else.

Thanks for letting me know about this new method.
I believe, the usage for our case is:
EXPORT_SYMBOL_GPL_FOR_MODULES(copy_to_kernel_nofault, "kasan_test");

>
> "might".  It depends on how "exploit code" might get hold of the
> symbol.  Perhaps you/we can discuss this further.  Is the problem that
> copy_to_kernel_nofault() is non-static?  Or it the problem that
> "exploit code" is itself a kernel module?

I haven't verified this, but theoretically, it's a handy
=E2=80=9Cwrite-anywhere-safely=E2=80=9D ROP gadget.
Assume the attacker has already gained an arbitrary RW primitive
via a UAF/OOB bug. Instead of stitching together
prepare_kernel_cred() + commit_creds(), which is a common path
of using exported symbols to achieve privilege escalation.
This path needs two symbols and register juggling.
With exported copy_to_kernel_nofault() they can do this:

/* Pseudocode of exploit for a ROP stage running in kernel context */
        struct cred *cred =3D leaked_pointer;
        rop_call(copy_to_kernel_nofault, &cred->uid, &zero, 4)

copy_to_kernel_nofault() disables page-faults around the write,
so even if cred corupts a guard-page, the write will not crash.

>
> In other words, a fuller investigation of how this export presently benef=
its
> exploiters would help us understand how much
> EXPORT_SYMBOL_GPL_FOR_MODULES() will improve the situation.
>

Please let me know if I should send v3 with using
EXPORT_SYMBOL_GPL_FOR_MODULES(copy_to_kernel_nofault, "kasan_test");

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgSBszyEr4zRqMbnoA0PEnZQNy8_ZKTMtwm-Nkho5MePg%40mail.gmail.com.
