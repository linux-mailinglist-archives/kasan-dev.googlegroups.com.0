Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXFKR6PQMGQE3FQBHKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C4968F3E9
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 18:01:18 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id c9-20020a9d67c9000000b0068d17bf4c93sf9297146otn.7
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 09:01:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675875677; cv=pass;
        d=google.com; s=arc-20160816;
        b=SAlLKv87aiXuDpJLOLFWdgUmBVf2WlYlkXux/G/zjiNoH+eo7jtktResGm+U8HEOQ5
         K+36o5gAKYm6rKnAAv/6K7NwWR786+0mtjmLNEV1Qpc0rWEmfCqTW9s5UrKUwb6W0opI
         d+Yz0hLkRZgkKKuMsD9UNqAMfxvzjcNvQFHWj3CP/YYMRfNNC+6zpesyg0l6bXnKyw0b
         ntZayJxVgjgBMnKsScd01Br+MJrFUMaVHInD/wK9zq+/rXBqXMrtE88qm4vhuZwc2YEF
         7D9jn4Ub+RiwDcRs10otfwiUzQm1VvmyI8uBT8Rik3XcPkV77eJotxEP/k3mJwJlZDiH
         KD7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U0H9p52G+++IuSrvmXmt6k/Yd3smOt0py4BrG+lSuhw=;
        b=wcDr+KpTdl/uGzRSlw/BydKlk7q/Ma1tqpSs+g+UAxyWCMKGWRvjbQ1ruyt6mnovE+
         R+J2HVCrQZaVi1JUdtqurqi0Ax+o10TyNlIrbVZrDhtcvEoIZ++10SldHUmHYStscstf
         6upLynt1ub0kwN9w0HRf1Iprs9HrjWb4l2T0OIHamjglfw+/zut8DQB0rvplcPTjqQ6D
         JYd6TPcBvz5FtAz9ohqJ5/eZbQsSUlnMKKrY8KELZmbtDfwYkUyxh7IGuotHGxPashbW
         RFOse552xlV4ElZ0d5C4gnUIoLdskPyHDxfPzlnVZrpokjMSYiY0UhsgZ7vCwUoPtg3U
         h4XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IYDBhhuM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U0H9p52G+++IuSrvmXmt6k/Yd3smOt0py4BrG+lSuhw=;
        b=GN+9SX/HaEt44DO6mRhOOwOZYsoOVVgR1hu6ZNN7KqLKExX6kbi+HhZHzsvOMz9GZw
         s7My+JVZuJbqovV+xkLtGYLh1kCrXLusW5T+8slsQLjqucNwqZVuH3eeb26of8PPhzNW
         vag1WjPGaw930C29CYqKkllFn5TIuKWmmMybSkMyTg89Wp0JGxmsl8ghu4dbxQsMMKaR
         G6Tn+6AxhOOwKFudnEfbecL1Gwg/t0v2IF2ZxiDAdlAE/HSa5uXnSb0lQe0yhiHzEC8s
         nkVx71jFEIZYCmOD3IcVI3iG6Dk+jZ4qYOoXmvgF6uLxymAsg7bPV/2qhsly8HxooSAY
         Kbrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=U0H9p52G+++IuSrvmXmt6k/Yd3smOt0py4BrG+lSuhw=;
        b=vYvChkFa3DZ2cZ+CsgJkVqO0B1h2bA79HA5/KVuDNaAM4UDJbKe0YVuY70pSb1iH8E
         bi4LalD32kYTfZT9b5dbrNY2zgyhWeFUDH1g8nLaiAmylcLx5ZC28Fd7tE7yGlagJ44I
         fKENaDKohN3es/9W8xSh6kp+NLSOtSwMZK0XfTWN+X1q7y9Q1tXcUZ95re5PG2HGthaX
         A2OX+C/Z66GJvfBdwH00XSRM9Iv9zqItZJJc/dVJI949JAEq8doMrhZ9MoYNyDH0puev
         RcqX8Mahl7R1Expw1VNzXoJBIIFAFU5yAj2riCt96bMKzT9GdSDrh+jIfbuEdVeiyBxe
         YopA==
X-Gm-Message-State: AO0yUKWCn36aLEz9O3xR3n91116AvYRhbNQvUdVPOl/xk+2/mrpudQ1N
	GkdBLBWxST0rTJ1lkXwyB5c=
X-Google-Smtp-Source: AK7set94c9Wm7HWxESs3XjF3JSKPPJZVrTthlV31rFDjbeP9CzMo6yKs1DKe0DGoWaJUVf+RJK8Mig==
X-Received: by 2002:a9d:4e91:0:b0:686:6392:ed38 with SMTP id v17-20020a9d4e91000000b006866392ed38mr649331otk.22.1675875676703;
        Wed, 08 Feb 2023 09:01:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f00a:0:b0:36e:b79c:1343 with SMTP id o10-20020acaf00a000000b0036eb79c1343ls6002492oih.7.-pod-prod-gmail;
 Wed, 08 Feb 2023 09:01:16 -0800 (PST)
X-Received: by 2002:a05:6808:4088:b0:37a:c1ea:2fb with SMTP id db8-20020a056808408800b0037ac1ea02fbmr3317836oib.9.1675875675845;
        Wed, 08 Feb 2023 09:01:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675875675; cv=none;
        d=google.com; s=arc-20160816;
        b=u7O1maN8xB0MfCxYaHGSTEHtUjn8xJsAOWxYD/XVMccqEC+brvIMIOIvF+rr4Yh/BR
         T4ry1tdzoQdL+iKfZSsBLlSCWz2QvcbmferMKiPAxRGL5qXqxLvfRMQrRzgf4HswMxFC
         tOFMuUNKhtAkL/QVS4UtMpWS4FbDiqgOX2RxpIjpMDBtxXrXuwcx8jL+S97LufhUKMLH
         OR+xqLugm9oIwWORTxppM9XfgUvJlWhgyAx3HuEuYnBDxsOlg+EfWI6wzfWBQBlWMRK5
         zgGvxeOcgwsgDhxtT4T4Fx8p/LISbVVMe1d1aPFTWkAJMGJfyq3H3W7Ky8Tds4O0j0Dl
         aojA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xXdBKFQFjb45PJbE0WfevTYuOvd7Ed4TIGS1v3lQONw=;
        b=ubdT3odaxB9xx+8ELJ8sRqLKdtpSIaPvesBRADHqdHXlQIoJbHQwpWFAUDwHkFb6i2
         6KWLaD0plEDvUWlbFh5t7sBvbdytE9fW63XS41Akn71gySXLVwCdyUe7yUCTfqYwk/Ep
         ePubdRVGH1CGxEPQK4zhx2Ewbz9sNvieENHR/7tmyti4vnBECzjsDwWhrsMw6ANrA01k
         C053f+HgH8iojyCTssJXUmU/yK/nkgnKmTVnIko8ef7YwFZJ1gyJQgfgey2o1RdJPdTk
         mX02/ozn8gUmWq9K17b5fNIUX8GnQ4q21ruSrTLZCYiM0fcnHugRCnoTGEnBSxavESYt
         rUAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IYDBhhuM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id s22-20020a05680810d600b0036bbb25d978si1777864ois.3.2023.02.08.09.01.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Feb 2023 09:01:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-520dad0a7d2so242169207b3.5
        for <kasan-dev@googlegroups.com>; Wed, 08 Feb 2023 09:01:15 -0800 (PST)
X-Received: by 2002:a81:9e07:0:b0:527:b49f:b89 with SMTP id
 m7-20020a819e07000000b00527b49f0b89mr937260ywj.176.1675875675180; Wed, 08 Feb
 2023 09:01:15 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org> <20230208164011.2287122-2-arnd@kernel.org>
In-Reply-To: <20230208164011.2287122-2-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Feb 2023 18:00:38 +0100
Message-ID: <CANpmjNNYcVJxeuJPFknf=wCaapgYSn0+as4+iseJGpeBZdi4tw@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: disable ftrace in kmsan core code
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Arnd Bergmann <arnd@arndb.de>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IYDBhhuM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 8 Feb 2023 at 17:40, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> objtool warns about some suspicous code inside of kmsan:
>
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_n+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_n+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_1+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_1+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_2+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_2+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_4+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_4+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_8+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_8+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_instrument_asm_store+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_chain_origin+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_poison_alloca+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_warning+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: __msan_get_context_state+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: kmsan_copy_to_user+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: kmsan_unpoison_memory+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: kmsan_unpoison_entry_regs+0x4: call to __fentry__() with UACCESS enabled
> vmlinux.o: warning: objtool: kmsan_report+0x4: call to __fentry__() with UACCESS enabled
>
> Similar code already exists in kasan, which avoids this by skipping
> ftrace annotations, so do the same thing here.
>
> Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kmsan/Makefile | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
> index 98eab2856626..389fd767a11f 100644
> --- a/mm/kmsan/Makefile
> +++ b/mm/kmsan/Makefile
> @@ -16,6 +16,14 @@ CC_FLAGS_KMSAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
>
>  CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)

That means this CFLAGS_REMOVE.o didn't work, right? Can it be removed?

> +# Disable ftrace to avoid recursion.
> +CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_hooks.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_instrumentation.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
> +
>  CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
> --
> 2.39.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNYcVJxeuJPFknf%3DwCaapgYSn0%2Bas4%2BiseJGpeBZdi4tw%40mail.gmail.com.
