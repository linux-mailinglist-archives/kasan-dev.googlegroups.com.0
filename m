Return-Path: <kasan-dev+bncBCMIZB7QWENRBZ4EXLBQMGQE3AAM3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 67BBFAFECA7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 16:53:29 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3a50816ccc6sf11412f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 07:53:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752072809; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hn3m51R5e1LNDn9LqqsP5L+62uIjxOUDt/v/S/17uERl7Bge4YABDe4ZvzDHChsVnk
         0I6KsNBZqcB5hCyOPoxI3mkRQJkAF6HXZbJI26e/EU5c834tcPy0ZlVZwLPeBt/e2SG/
         CV+aNnn8bO4/8B4VVzmFF1+G7uaWKLH/XPcojxBx022qCZFsKQbL5qrOKQoOEe7K7kDI
         1jRj6SqYuWVCxIuMDYbJYiWTSY/fqTdRpUQUu4VwxBhNdXgOM41naTIyzyVctpLi6+D2
         9Zgw8U9CpeMKxk9w5D04qBc4O/2J4fI3gEV+JFAUQus8I4VXG5ahrQ5sYg9io1gNNA8e
         H1Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xUFg3ox00knLxSbbO11FDpzfHyhLoeqIi18QPYcOdkQ=;
        fh=OS6K28SuO/Y+NGO/24ukR3Uo7ct88GStB/K4pYMehq8=;
        b=SolnjWwMR6M5pWuRCUHUrQGudtPykQtIK0lSg12aHFJ0KgKI9x/Ymo1y7aEFrf00xt
         V9MB7l5yeBwIsnSHkahA2xXQvL2jrKnehoP0bRhNp0qUsW1kuRdLn+C+zKRvJBy1AKE/
         by7cn2H/IXkQATcog+KGvIt80khG6oMuF2gKk3QYoqmoFkVgfCHcaNLvWQ1ZtVBidjfJ
         r8CeNxpNc1CK2FHdGZtR49Pu2ITNXwZah8L0bkbZI6nWq4AUKjSE1pn4Sw+jdVYb55dC
         37pBSO65w4IPdY1nw9eEOcuDF26XKM6Ho0JOaIyyiXicm/kv8BoSvZITcF+xP1q376p6
         5eaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WcVSeBQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752072809; x=1752677609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xUFg3ox00knLxSbbO11FDpzfHyhLoeqIi18QPYcOdkQ=;
        b=Y6D/GOUQZX32G+fGR+Befxkho/n8J+d7fDzGWxd2/WKy1UOVKxTR8TPulhsW+2q+Mf
         CgdT/BGStBPuakgGdpFwc/Z2FhxwpTmt0XQTCtjg4jttwGZMxsczDvbNNZC+Sd9fyvWX
         2SS7hoLegZGNKcWDRvUIYW64LhBDbxzXVxyB6z9aU52/ibHEX6YTC6Qnp9I0mIPlzMHr
         wE8cOHppE88b+4sqqMxZfvQLsBwVGJFVfxc0qxcyBnvKMyB34JM70vrhmBup2yHA3j/5
         Sbf1GCoaX0v05rH715StPR5IxMcP/73l6rMsv1Zq/xTz+MclPvf8mJxxyqh+R1HYVmwK
         E7jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752072809; x=1752677609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xUFg3ox00knLxSbbO11FDpzfHyhLoeqIi18QPYcOdkQ=;
        b=qK90x22kvwuHjKYlH0jdLOi+pJbbzQmrZKYDN7wNlLDU+v8GRfOrK+udFuHNBt+XdQ
         tiCWX6YddgC9ON3i4gwxCqumMCJHRkBwu6Zz7toskUS9dpLIickR59q5vg/xo8YBESYw
         fc8nknlUq/fdF73N9Od1yTZEaZxm2xcs/WWw1Ca2QZgGdcuT3MLoRqXgI1uHhktmkrEv
         ZGea6s5g8G5hILxRufvpfV9DX9Aw+HSs6DCrNN5oifiC/fFD7BsWlYi9+VVIi+xewsFC
         rgUaSTBg8KVqpAtSw2OtT9CwGYEreOoisCEnqm2eIEXpCa1Z3Gzwi+r1J4x8rjC/DkFm
         5qDA==
X-Forwarded-Encrypted: i=2; AJvYcCWByAsI772LzQ/wMQT8JjGE+9iFStorfjq6NqVDV7P3ZT9plcW5rjib+T+LfAMRnalWq7cEUQ==@lfdr.de
X-Gm-Message-State: AOJu0YyoE20XtPd9OpTPOgJwxiDX6bowXgr3bVLtRbSqxJ9sPpn/L3Il
	BUzdzjJNtJxj8LSF6CFwu9RWrbVho14f8W/cp4M+kw2on6dJTRlvMayd
X-Google-Smtp-Source: AGHT+IGEvdAyLeElhPymO9ljpyhSuM2plUSfS2nr2G9aPApmSSnne46Zn1tGaD8ixyeC5s9c02beKQ==
X-Received: by 2002:a05:6000:26c9:b0:3a4:e480:b5df with SMTP id ffacd0b85a97d-3b5e45470a7mr2867245f8f.44.1752072808385;
        Wed, 09 Jul 2025 07:53:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdA3XfnUxIIZ5yGes0k0/MXd5/Df31YGh93YBb+jcxbRA==
Received: by 2002:a5d:64e6:0:b0:3a5:89d7:ce0d with SMTP id ffacd0b85a97d-3b49744b9fdls2734343f8f.0.-pod-prod-09-eu;
 Wed, 09 Jul 2025 07:53:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdZhsjOmLvYylZsuA4+cW/dQgEOEAandqpU25sKOLmTW+/WHzbr4fr0WD6pV61VbUB3xE+Bw+WDhQ=@googlegroups.com
X-Received: by 2002:a05:6000:26cd:b0:3a6:e1bb:a083 with SMTP id ffacd0b85a97d-3b5e4513991mr2620769f8f.25.1752072805741;
        Wed, 09 Jul 2025 07:53:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752072805; cv=none;
        d=google.com; s=arc-20240605;
        b=AlEhvdeQFOoeOrmEVvM7/ZFrF9CulPprVBi0dkyGfdQ5plwTdg64Z1a+vY4WzSIESv
         DNy29nX0f1f7fIY3M0XGxengpLWP7kx/WiLNhLO/EWjOK6jeHdLe3urIBu7N+9/rO/sk
         FnvRRtlO0C0v8UKJtQWzCXBF0Xmovriu1oHo2YeJnOUKYnKcRqRD/0c5rOCphHVkvjRM
         uBD3GXdsxIn0B1hpaYVd9iW475NiC6OedlfDAkCW3YJA+SZMKhbJQhQMrAvBcmeO0NHD
         RPkkhrJepHIlbXeEpsK+3oEW5c+i5K8YObfiRiu0wBPo6eM0zdXjt4tsDSv+sJsUIsti
         0atA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cOYdoaWyY3uQXdbZORoJMC4n+n/vVc/HUyRRArbBJO4=;
        fh=QGRjCjUkzNSET8tJNfA4TE9BNJxnNWG54flRkGe5KSk=;
        b=IQaE3GqpsqdzZNICMTegO2JqfMNi4pvBYQ3VhcEWNFZ54CqcwRyV+JEYOrZxwHyph1
         crq2j7u7E+jnMY0CkpirNL7bEijdT5Qr3Vl4+SffxiE1ataoLbrpT7zKKa6GwfkdFmlB
         2w4tqm6vOkc614SdTGB0HbqWbwuMxKy6W5Ia8S1Zuddnn98a+kSUvlHr0iCMdlFsVK5/
         vLoNwYI9hfF1lsYApKoW4dN8foaTrYyYmU0GMMmDVyUaSEP0ORc8z9mdIROPiJiOHsNG
         2t9WSIASIw2Lh13ph30v1i1a4lUygJNmkhJSxXTi2WgogPbCWJaJ7gwWiF/MxGWoXhOW
         SYUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WcVSeBQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b47156a702si249127f8f.4.2025.07.09.07.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 07:53:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-555024588b1so5604395e87.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 07:53:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUT+ZfhiMk0Dm0lUqNFLVuL8qwa4HtHNRsZ6TO5YVWOnqtCGwyLCT0ikcNS/sHY1ycLewBQ4Umlpqc=@googlegroups.com
X-Gm-Gg: ASbGncthgjQIbJXG47kgWjqVOGuDr85IMufV5wW9sJt/HykElU36hFnre/xFRNhTo/H
	Cmj6BqxttyT9S35ugY+KatxPw+9ZWhel/LbKHx2JmvbtoMhDgND6fkxMPkGaX0mkEVr6mxdOPhw
	jmfGBbEUQrIOdIP1YBl1UmzdKPjvgvN8SMI2puEdmGCqRii9oS992WZyUrbcrYNmp9AFD9+acRQ
	1mq
X-Received: by 2002:a2e:7014:0:b0:32b:a85f:c0b8 with SMTP id
 38308e7fff4ca-32f483e4ed6mr8361631fa.9.1752072804781; Wed, 09 Jul 2025
 07:53:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-6-glider@google.com>
In-Reply-To: <20250626134158.3385080-6-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 16:53:13 +0200
X-Gm-Features: Ac12FXxPwTmllLByY7RsdoeFXIB5dcOLBahesrToj0d2F-vfnSS3_ZxXdIirMvk
Message-ID: <CACT4Y+ahHYybYkvT8z8rzr55mmSp-_EDCVZsh+f_TX9mnCJoiA@mail.gmail.com>
Subject: Re: [PATCH v2 05/11] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WcVSeBQb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
>
> Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
> are inserted by Clang when building with coverage guards.
> These functions can be used to detect initialization order fiasco bugs
> in the userspace, but it is fine for them to be no-ops in the kernel.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

>
> ---
> Change-Id: I7f8eb690a3d96f7d122205e8f1cba8039f6a68eb
>
> v2:
>  - Address comments by Dmitry Vyukov:
>    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
>  - Move this patch before the one introducing CONFIG_KCOV_UNIQUE,
>    per Marco Elver's request.
> ---
>  mm/kasan/generic.c | 18 ++++++++++++++++++
>  mm/kasan/kasan.h   |  2 ++
>  2 files changed, 20 insertions(+)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e76..b0b7781524348 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -238,6 +238,24 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
>  }
>  EXPORT_SYMBOL(__asan_unregister_globals);
>
> +#if defined(CONFIG_KCOV_UNIQUE)
> +/*
> + * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
> + * when the user requests building with coverage guards. In the userspace, these
> + * two functions can be used to detect initialization order fiasco bugs, but in
> + * the kernel they can be no-ops.
> + */
> +void __asan_before_dynamic_init(const char *module_name)
> +{
> +}
> +EXPORT_SYMBOL(__asan_before_dynamic_init);
> +
> +void __asan_after_dynamic_init(void)
> +{
> +}
> +EXPORT_SYMBOL(__asan_after_dynamic_init);
> +#endif
> +
>  #define DEFINE_ASAN_LOAD_STORE(size)                                   \
>         void __asan_load##size(void *addr)                              \
>         {                                                               \
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e649..c817c46b4fcd2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
>
>  void __asan_register_globals(void *globals, ssize_t size);
>  void __asan_unregister_globals(void *globals, ssize_t size);
> +void __asan_before_dynamic_init(const char *module_name);
> +void __asan_after_dynamic_init(void);
>  void __asan_handle_no_return(void);
>  void __asan_alloca_poison(void *, ssize_t size);
>  void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
> --
> 2.50.0.727.gbf7dc18ff4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BahHYybYkvT8z8rzr55mmSp-_EDCVZsh%2Bf_TX9mnCJoiA%40mail.gmail.com.
